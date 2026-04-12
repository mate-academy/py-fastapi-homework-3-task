import secrets
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import get_user_by_email, create_user, get_activation_token
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
from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        return await create_user(db, email=user.email, password=user.password)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    token_record = await get_activation_token(db, db_user.id)
    if not token_record or token_record.token != data.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    current_time = datetime.now(timezone.utc)

    if expires_at < current_time:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    try:
        db_user.is_active = True
        await db.delete(token_record)

        await db.commit()
        return {"message": "User account activated successfully."}

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during activation.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def password_reset_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)
    try:
        if db_user and db_user.is_active:
            await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))
            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(hours=1)
            new = PasswordResetTokenModel(user_id=cast(int, db_user.id), token=token, expires_at=expires)
            db.add(new)
            await db.commit()
    except Exception:
        await db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def password_reset_complete(reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, reset_data.email)
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    result = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
    )
    token_record = result.scalar_one_or_none()
    if not token_record or token_record.token != reset_data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    hashed_password = hash_password(reset_data.password)

    try:
        db_user._hashed_password = hashed_password
        await db.delete(token_record)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await get_user_by_email(db, login_data.email)
    if not db_user or not verify_password(login_data.password, db_user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        {
            "sub": db_user.email,
            "user_id": db_user.id
        }
    )
    refresh_token = jwt_manager.create_refresh_token(
        {
            "sub": db_user.email,
            "user_id": db_user.id
        }
    )
    try:
        new_refresh = RefreshTokenModel(user_id=db_user.id, token=refresh_token)
        db.add(new_refresh)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh(
        data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
        if user_id is None or not isinstance(user_id, int):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token payload."
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalar_one_or_none()
    if not token_record or token_record.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        {
            "sub": user.email,
            "user_id": user.id
        }
    )

    return {
        "access_token": new_access_token
    }
