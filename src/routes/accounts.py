from datetime import datetime, timezone, timedelta
from typing import cast

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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema, UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user_data.email} already exists."
            )

        hashed_password = hash_password(user_data.password)
        group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )

        if group is None:
            raise HTTPException(
                status_code=500,
                detail="An error occurred during user creation."
            )

        db_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_password,
            group=group
        )
        db.add(db_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user_id=db_user.id
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        ) from exc


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    current_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if not current_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if current_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    user_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == current_user.id,
            ActivationTokenModel.token == user_data.token,
        )
    )

    if user_token is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = user_token.expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    try:
        current_user.is_active = True

        await db.delete(user_token)
        await db.commit()
        return MessageResponseSchema(message="User account activated successfully.")

    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during account activation."
        ) from exc


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    current_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if not current_user or not current_user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions.",
        )

    user_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == current_user.id
        )
    )

    if user_token is not None:
        await db.delete(user_token)
        await db.flush()

    new_user_token = PasswordResetTokenModel(
        user_id=current_user.id
    )

    db.add(new_user_token)
    await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions.",
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        current_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )

        if current_user is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )

        user_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == current_user.id
            )
        )

        if not current_user.is_active:
            if user_token is not None:
                await db.delete(user_token)
                await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )

        user_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == current_user.id,
            )
        )

        if user_token is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        if user_token.token != user_data.token:
            await db.delete(user_token)
            await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        expires_at = user_token.expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            await db.delete(user_token)
            await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        current_user.password = user_data.password
        await db.delete(user_token)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        ) from exc


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):

    current_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if current_user is None or not current_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": current_user.id},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )

    user_refresh_token = RefreshTokenModel.create(
        token=refresh_token,
        user_id=current_user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
    )

    user_access_token = jwt_manager.create_access_token(
        data={"user_id": current_user.id}
    )
    try:
        db.add(user_refresh_token)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=user_access_token,
            refresh_token=user_refresh_token.token,
            token_type="bearer",
        )

    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        ) from exc


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def access_token_refresh(
    user_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(
            user_data.refresh_token
        )
    except BaseSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    db_refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == user_data.refresh_token
        )
    )

    if not db_refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found.",
        )

    user_id = decoded_refresh_token.get("user_id")

    if not isinstance(user_id, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token.",
        )

    current_user = await db.get(UserModel, user_id)

    if not current_user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if db_refresh_token.user_id != user_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid refresh token."
        )

    user_access_token = jwt_manager.create_access_token(
        data={"user_id": current_user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=user_access_token,
    )
