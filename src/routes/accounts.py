import secrets
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError, ExpiredSignatureError
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface

from database import models
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserLoginRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    MessageResponseSchema,
)

from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == user_data.email)
    )
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt = select(models.UserGroupModel).where(
        models.UserGroupModel.name == models.UserGroupEnum.USER
    )
    result = await db.execute(stmt)
    user_group = result.scalars().first()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found",
        )

    try:
        new_user = models.UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            is_active=False,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = models.ActivationTokenModel(
            token=secrets.token_urlsafe(32),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            user_id=new_user.id,
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email,
        )

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(models.ActivationTokenModel).where(
            models.ActivationTokenModel.user_id == user.id
        )
    )
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    current_time = datetime.now(timezone.utc)

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token_record.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if expires_at < current_time:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    await db.refresh(user)
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(
            select(models.PasswordResetTokenModel).where(
                models.PasswordResetTokenModel.user_id == user.id
            )
        )
        old_token = (
            (
                await db.execute(
                    select(models.PasswordResetTokenModel).where(
                        models.PasswordResetTokenModel.user_id == user.id
                    )
                )
            )
            .scalars()
            .all()
        )
        for t in old_token:
            await db.delete(t)

        reset_token = models.PasswordResetTokenModel(
            token=secrets.token_urlsafe(32),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user_id=user.id,
        )
        db.add(reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(
        select(models.PasswordResetTokenModel).where(
            models.PasswordResetTokenModel.user_id == user.id
        )
    )
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    current_time = datetime.now(timezone.utc)
    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token_record.token != data.token or expires_at < current_time:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalars().first()

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        new_refresh = models.RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(new_refresh)
        await db.commit()
        await db.refresh(new_refresh)

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
    except Exception as e:
        # Проверяем текст ошибки
        if "expired" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token.",
            )

    result = await db.execute(
        select(models.RefreshTokenModel).where(
            models.RefreshTokenModel.token == payload.refresh_token
        )
    )
    refresh_token = result.scalars().first()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    result = await db.execute(
        select(models.UserModel).where(models.UserModel.id == decoded["user_id"])
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": decoded["user_id"]})

    return TokenRefreshResponseSchema(access_token=access_token)
