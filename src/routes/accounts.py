from datetime import datetime, timezone
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
from exceptions import BaseSecurityError, TokenExpiredError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(
        payload: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {payload.email} already exists.")

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(stmt)
    user_group = result.scalars().first()

    new_user = UserModel.create(
        email=payload.email,
        raw_password=payload.password,
        group_id=user_group.id
    )
    db.add(new_user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=new_user.id)
    db.add(activation_token)

    try:
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return new_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
        payload: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == payload.token
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if not activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if activation_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
        payload: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    GENERIC_MESSAGE = "If you are registered, you will receive an email with instructions."

    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        return MessageResponseSchema(message=GENERIC_MESSAGE)

    stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result = await db.execute(stmt)
    existing_token = result.scalars().first()

    if existing_token:
        await db.delete(existing_token)
        await db.flush()

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)
    await db.flush()

    try:
        await db.commit()
        await db.refresh(reset_token)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return MessageResponseSchema(message=GENERIC_MESSAGE)


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == payload.token
    )
    result = await db.execute(stmt)
    reset_token = result.scalars().first()

    if not reset_token:
        stmt = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        result = await db.execute(stmt)
        existing_token = result.scalars().first()
        if existing_token:
            await db.delete(existing_token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user.password = payload.password
    await db.delete(reset_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )
    db.add(refresh_token_record)
    try:
        await db.commit()
        await db.refresh(refresh_token_record)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        refresh_token_decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    user_id = refresh_token_decoded["user_id"]

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()

    if not refresh_token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
