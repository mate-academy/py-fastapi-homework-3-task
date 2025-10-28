from datetime import datetime, timezone, timedelta
from typing import cast
import secrets

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from src.config import get_jwt_auth_manager, get_settings, BaseAppSettings
from src.database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from src.security.interfaces import JWTAuthManagerInterface
from src.schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from src.crud.users import create_user
from src.security.passwords import hash_password, verify_password
from src.utils.transactions import transaction_atomic

router = APIRouter()

ACCESS_TOKEN_EXPIRATION = timedelta(hours=6)
REFRESH_TOKEN_EXPIRATION = timedelta(days=7)


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema,
                   db: AsyncSession = Depends(get_db)) -> UserRegistrationResponseSchema:
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A user with this email {user.email} already exists.")
    return await create_user(db, user)


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(payload: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == payload.token))
    token = result.scalar_one_or_none()
    if not token or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    result = await db.execute(select(UserModel).where(UserModel.id == token.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")
    user.is_active = True
    await db.delete(token)
    await db.commit()
    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password(payload: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    response = await db.execute(select(UserModel)
                                .options(joinedload(UserModel.password_reset_token))
                                .where(UserModel.email == payload.email))
    user = response.scalar_one_or_none()
    if user and user.is_active:
        if user.password_reset_token:
            db.delete(user.password_reset_token)
        token = PasswordResetTokenModel(user_id=user.id,
                                        token=secrets.token_urlsafe(32),
                                        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)))
        db.add(token)
        await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
@transaction_atomic
async def reset_password_complete(payload: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        response = await db.execute(select(UserModel)
                                    .options(joinedload(UserModel.password_reset_token))
                                    .where(UserModel.email == payload.email))
        user = response.scalar_one_or_none()
        if user:
            if user.password_reset_token:
                if (
                    user.is_active
                    and user.password_reset_token.expires_at.replace(tzinfo=timezone.utc) >= datetime.now(timezone.utc)
                    and user.password_reset_token.token == payload.token
                ):
                    user._hashed_password = hash_password(payload.password)
                    await db.delete(user.password_reset_token)
                    await db.commit()
                    return {
                        "message": "Password reset successfully."
                    }
                await db.delete(user.password_reset_token)
                await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(payload: UserLoginRequestSchema,
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                db: AsyncSession = Depends(get_db)):
    response = await db.execute(select(UserModel)
                                .options(joinedload(UserModel.group))
                                .where(UserModel.email == payload.email))
    user = response.scalar_one_or_none()
    if not user or not verify_password(payload.password, user._hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")
    temp_token = jwt_manager.create_refresh_token(
        data={
            "user_id": user.id,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRATION
        },
        expires_delta=REFRESH_TOKEN_EXPIRATION
    )
    refresh_token = RefreshTokenModel.create(user.id, 7, temp_token)
    try:
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while processing the request.")
    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": str(user.group_id),
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRATION
        },
        expires_delta=ACCESS_TOKEN_EXPIRATION
    )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token.token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(payload: TokenRefreshRequestSchema,
                               jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                               db: AsyncSession = Depends(get_db)):
    try:
        jwt_manager.decode_refresh_token(payload.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    response = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token))
    refresh_token = response.scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")
    if refresh_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    response = await db.execute(select(UserModel).where(UserModel.id == refresh_token.user_id))
    user = response.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": str(user.group_id),
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRATION
        },
        expires_delta=ACCESS_TOKEN_EXPIRATION
    )
    return {
        "access_token": access_token
    }
