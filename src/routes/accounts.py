from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetCompleteRequestSchema, PasswordResetRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

ASession = Annotated[AsyncSession, Depends(get_db)]
Settings = Annotated[BaseAppSettings, Depends(get_settings)]
TokenManager = Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)]

RESPONSE_MESSAGE = "If you are registered, you will receive an email with instructions."


async def get_user_by_email(
        session: ASession,
        email: str
) -> UserModel | None:
    return await session.scalar(
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token),
            joinedload(UserModel.password_reset_token),
        )
        .where(UserModel.email == email)
    )


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        session: ASession,
        user_data: UserRegistrationRequestSchema,
):
    if await session.scalar(
            select(UserModel)
            .where(UserModel.email == user_data.email)
    ):
        raise HTTPException(
            status_code=409,
            detail="A user with this email "
                   f"{user_data.email} already exists."
        )
    group = await session.scalar(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not group:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    db_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=group.id,
    )
    try:
        session.add(db_user)
        await session.flush()
        act_token = ActivationTokenModel(user_id=cast(int, db_user.id))
        session.add(act_token)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    await session.refresh(db_user)
    return UserRegistrationResponseSchema(
        id=db_user.id,
        email=db_user.email
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
        session: ASession,
        activation: UserActivationRequestSchema,
):
    db_user = await get_user_by_email(session, activation.email)
    if db_user is not None and db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    token = db_user.activation_token if db_user else None
    if (
            token is None
            or token.token != activation.token
            or cast(datetime, token.expires_at)
            .replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    try:
        db_user.is_active = True
        await session.delete(token)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user activation."
        )
    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_user_password(
        session: ASession,
        user: PasswordResetRequestSchema
):
    db_user = await get_user_by_email(session, user.email)
    if db_user is None or not db_user.is_active:
        return MessageResponseSchema(
            message=RESPONSE_MESSAGE
        )
    try:
        if db_user.password_reset_token is not None:
            await session.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.user_id == db_user.id)
            )
        reset_token = PasswordResetTokenModel(user_id=cast(int, db_user.id))
        session.add(reset_token)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        return MessageResponseSchema(
            message=RESPONSE_MESSAGE
        )
    return MessageResponseSchema(
        message=RESPONSE_MESSAGE
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def complete_password_reset(
        session: ASession,
        user_data: PasswordResetCompleteRequestSchema,
):
    db_user = await get_user_by_email(session, user_data.email)
    reset_token = db_user.password_reset_token if db_user else None
    if (
            db_user is None
            or not db_user.is_active
            or reset_token is None
            or reset_token.token != user_data.token
            or cast(datetime, reset_token.expires_at)
            .replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        if db_user and reset_token is not None:
            try:
                await session.delete(reset_token)
                await session.commit()
            except SQLAlchemyError:
                await session.rollback()
                raise HTTPException(
                    status_code=500,
                    detail="An error occurred while resetting the password."
                )
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    try:
        db_user.password = user_data.password
        await session.delete(reset_token)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK
)
async def login_user(
        session: ASession,
        user: UserLoginRequestSchema,
        jwt_manager: TokenManager,
        settings: Settings
):
    db_user = await get_user_by_email(session, user.email)
    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )
    data = {"user_id": db_user.id}
    refresh_token_jwt = jwt_manager.create_refresh_token(data)
    try:
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_jwt
        )
        session.add(refresh_token)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )
    acs_token_jwt = jwt_manager.create_access_token(data)
    return UserLoginResponseSchema(
        access_token=acs_token_jwt,
        refresh_token=refresh_token_jwt,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def refresh_token(
        session: ASession,
        token: TokenRefreshRequestSchema,
        jwt_manager: TokenManager
):
    try:
        jwt_token = jwt_manager.decode_refresh_token(token.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(status_code=400, detail=str(error))
    user_id = jwt_token.get("user_id")
    token_record = await session.scalar(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == token.refresh_token)
    )
    if token_record is None or token_record.user_id != user_id:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    db_user = await session.get(UserModel, user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
