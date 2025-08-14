from datetime import datetime, timezone, timedelta
import secrets
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManager
from security.interfaces import JWTAuthManagerInterface
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from crud import (
    create_user,
    get_user_by_email,
    create_activation_token,
    get_user_token_by_email_and_token,
    activate_user_account,
    delete_activation_token,
    get_active_user_by_email,
    delete_existing_password_reset_tokens,
    create_password_reset_token,
    delete_password_reset_token,
    update_user_password,
    get_refresh_token_by_token,
    get_user_by_id,
)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )
    db_user = await create_user(db, user)
    await create_activation_token(db, db_user)
    return db_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    token_obj = await get_user_token_by_email_and_token(
        db, ActivationTokenModel, data.email, data.token
    )

    if not token_obj:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user = token_obj.user
    if user.is_active:
        raise HTTPException(
            status_code=400, detail="User account is already active."
        )

    await activate_user_account(db, user)
    await delete_activation_token(db, token_obj)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_password_user_account(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await get_active_user_by_email(db, data.email)

    if user:
        await delete_existing_password_reset_tokens(db, user)
        token = secrets.token_urlsafe(32)
        await create_password_reset_token(db, user, token)

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    token_obj = await get_user_token_by_email_and_token(
        db,
        PasswordResetTokenModel,
        data.email,
        data.token
    )

    async def raise_invalid_token():
        user = await get_user_by_email(db, data.email)
        if user:
            await delete_existing_password_reset_tokens(db, user)
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if not token_obj:
        await raise_invalid_token()

    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await delete_password_reset_token(db, token_obj)
        await raise_invalid_token()

    await update_user_password(db, token_obj.user, data.password)
    await delete_password_reset_token(db, token_obj)
    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    db_user = await get_user_by_email(db, data.email)
    if not db_user or not verify_password(data.password, db_user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token_expires = timedelta(minutes=30)
    access_token = jwt_manager.create_access_token(
        data={"sub": db_user.email},
        expires_delta=access_token_expires
    )
    refresh_token = jwt_manager.create_refresh_token(data={"sub": db_user.email})

    db_refresh_token = RefreshTokenModel(
        token=refresh_token,
        user_id=db_user.id
    )
    db.add(db_refresh_token)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=201)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    db_token = await get_refresh_token_by_token(db, data.refresh_token)
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    return {"access_token": access_token}
