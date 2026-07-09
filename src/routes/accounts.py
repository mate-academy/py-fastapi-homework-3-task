from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from exceptions import TokenExpiredError, InvalidTokenError

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
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def _is_token_expired(expires_at: datetime):
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_info: UserRegistrationRequestSchema
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == user_info.email)
        )

        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_info.email} already exists."
            )

        group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == user_info.role))
        user = UserModel.create(
            email=user_info.email,
            raw_password=user_info.password,
            group_id=group.id
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=user.id
        )
        db.add(activation_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    return user


@router.post("/activate/", status_code=status.HTTP_200_OK, response_model=MessageResponseSchema)
async def activate_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_token_info: UserActivationRequestSchema
):
    user = await db.scalar(
        select(UserModel). where(UserModel.email == user_token_info.email)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == user_token_info.token
        )
    )

    if not token or _is_token_expired(token.expires_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True

    db.add(user)
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_user_password_token(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_info: PasswordResetRequestSchema
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_info.email)
    )
    if not user:
        return MessageResponseSchema(
            message="If you are registered, you will"
                    " receive an email with instructions."
        )
    if not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will"
                    " receive an email with instructions."
        )

    invalid_reset_pass_tokens = await db.scalars(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    for token in invalid_reset_pass_tokens:
        await db.delete(token)

    new_reset_pass_tokens = PasswordResetTokenModel(
        user_id=user.id
    )

    db.add(new_reset_pass_tokens)
    await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will"
                " receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_user_password(
        db: Annotated[AsyncSession, Depends(get_db)],
        info_for_reset: PasswordResetCompleteRequestSchema
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == info_for_reset.email)
        )
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        token = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.token == info_for_reset.token)
        )
        token_user = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        if not token:
            if token_user:
                await db.delete(token_user)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )
        if _is_token_expired(token.expires_at):
            await db.delete(token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        await db.delete(token)
        user.password = info_for_reset.password
        db.add(user)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_info: UserLoginRequestSchema,
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        settings: Annotated[BaseAppSettings, Depends(get_settings)],
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == user_info.email)
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )
        if not user.verify_password(user_info.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )
        data_for_token = {"user_id": user.id}
        access_token = jwt_manager.create_access_token(data=data_for_token)
        refresh_token = jwt_manager.create_refresh_token(
            data=data_for_token,
            expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
        )
        refresh_token_db = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_db)
        await db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def get_new_refresh_token(
    db: Annotated[AsyncSession, Depends(get_db)],
    refresh_token: TokenRefreshRequestSchema,
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    refresh_token_db = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token.refresh_token)
    )

    if not refresh_token_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = await db.get(UserModel, refresh_token_db.user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if decoded_refresh_token["user_id"] != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )
