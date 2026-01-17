import secrets
import uuid
from datetime import datetime, timezone, timedelta

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from security.token_manager import (create_refresh_token,
                                   create_access_token)
import logging

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
from schemas.accounts import UserCreate, UserRead, ActivateResponse, ActivateRequest, PasswordResetRequest, \
    PasswordResetResponse, PasswordResetCompleteResponse, PasswordResetCompleteRequest, UserLoginResponse, \
    UserLoginRequest, RefreshTokenRequest, RefreshTokenResponse
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


async def create_user(db: AsyncSession, user: UserCreate) -> UserModel:
    hashed = hash_password(user.password)
    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed,
        group=UserGroupEnum.USER,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def create_activation_token(db: AsyncSession, user: UserModel) -> ActivationTokenModel:
    token = ActivationTokenModel(
        user_id=user.id,
        token=str(uuid.uuid4()),
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token


@router.post("/register/", response_model=UserRead,
             status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate,
                   db: AsyncSession = Depends(get_db),
                   ):
    try:
        result = await db.execute(select(UserModel)
                                  .where(UserModel.email == user.email))
        user_data = result.scalar_one_or_none()
        if user_data:
            raise HTTPException(status_code=409,
                                detail=f"A user with this email {user_data.email} already exists.")
        created_user = await create_user(db, user)
        await create_activation_token(db, created_user)

        return UserRead.model_validate(created_user)
    except SQLAlchemyError as e:
        logging.exception("Database error during user creation")
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )

@router.post("/activate/", response_model=ActivateResponse,)
async def activate_account(request: ActivateRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    result = await db.execute(select(ActivationTokenModel).
                              where(ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == request.token,))
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    db.add(user)
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}

@router.post("/password-reset/request/", response_model=PasswordResetResponse,)
async def password_reset(request: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = result.scalar_one_or_none()
    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        token_str = secrets.token_urlsafe(32)

        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=token_str,
            expires_at=expires_at,
        )
        db.add(new_token)
        await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }

@router.post("/reset-password/complete/", response_model=PasswordResetCompleteResponse,)
async def password_reset_complete(request: PasswordResetCompleteRequest, db: AsyncSession = Depends(get_db)):

    result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = result.scalar_one_or_none()
    if not user or user.is_active == False:
        raise HTTPException(status_code=400, detail="User not found or not active.")
    result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    token = result.scalar_one_or_none()
    if token != request.token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        hashed = hash_password(request.password)
        user._hashed_password = hashed
        db.add(user)
        db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

@router.post("/login/", response_model=UserLoginResponse)
async def user_login(request: UserLoginRequest, db: AsyncSession = Depends(get_db)):

    result = await db.execute(select(UserModel).where(UserModel.email == request.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(request.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if user.is_active is False:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_type = "bearer"
        await RefreshTokenModel.create(db, user_id=user.id, token=refresh_token, expired_at=expires_at)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": token_type
        }
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

@router.post("/api/v1/accounts/refresh/", response_model=RefreshTokenResponse)
async def refresh_token(data: RefreshTokenRequest,
                        db: AsyncSession = Depends(get_db),
                        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload.")
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token,
                                                        RefreshTokenModel.user_id == int(user_id)
                                                        ))
    token_entry = result.scalar_one_or_none()
    if not token_entry:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    result = await db.execute(select(UserModel).where(UserModel.id == token_entry.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token(subject=str(user.id))
    return {"access_token": access_token}
