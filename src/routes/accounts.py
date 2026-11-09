from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from config.settings import Settings
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
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserLoginResponseSchema
from schemas.accounts import MessageResponseSchema, UserActivationRequestSchema, PasswordResetRequestSchema, \
    PasswordResetCompleteRequestSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, \
    TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db_session: AsyncSession = Depends(get_db)
):
    result = await db_session.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )

    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    result = await db_session.execute(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = result.scalar_one_or_none()

    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found."
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )
        db_session.add(new_user)
        await db_session.flush()
        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db_session.add(activation_token)

        await db_session.commit()
        await db_session.refresh(new_user)
    except SQLAlchemyError:
        await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db_session: AsyncSession = Depends(get_db)
):
    stmt = (
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == user_data.email,
            ActivationTokenModel.token == user_data.token
        )
    )
    result = await db_session.execute(stmt)

    token_record = result.scalar_one_or_none()

    if not token_record or (
        cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = token_record.user

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db_session.delete(token_record)
    await db_session.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_password_reset_token(
        user_data: PasswordResetRequestSchema,
        db_session: AsyncSession = Depends(get_db)
):
    result = await db_session.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    user = result.scalar_one_or_none()
    if user and user.is_active:
        await db_session.execute(
            delete(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        reset_token = PasswordResetTokenModel(
            user_id=cast(int, user.id)
        )
        db_session.add(reset_token)
        await db_session.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def complete_reset_password(
        user_data: PasswordResetCompleteRequestSchema,
        db_session: AsyncSession = Depends(get_db)
):
    result = await db_session.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    result = await db_session.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    token_record = result.scalar_one_or_none()
    if (
        not token_record
        or token_record.token != user_data.token
        or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        < datetime.now(timezone.utc)
    ):
        if token_record:
            await db_session.delete(token_record)
            await db_session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = user_data.password
        await db_session.delete(token_record)
        await db_session.commit()
    except SQLAlchemyError:
        await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(
        message="Password reset successfully.",
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db_session: AsyncSession = Depends(get_db),
        settings: Settings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    result = await db_session.execute(
        select(UserModel)
        .where(
            UserModel.email == login_data.email
        )
    )

    user = result.scalar_one_or_none()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    jwt_refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token
        )

        db_session.add(refresh_token)
        await db_session.flush()
        await db_session.commit()
    except SQLAlchemyError:
        await db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    jwt_access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db_session: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(
            token_data.refresh_token
        )
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    result = await db_session.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == token_data.refresh_token)
    )

    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    result = await db_session.execute(
        select(UserModel)
        .where(UserModel.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    new_access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )
    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )
