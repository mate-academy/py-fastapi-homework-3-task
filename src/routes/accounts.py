from datetime import datetime, timezone, timedelta
from typing import cast
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import and_

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
from exceptions import TokenExpiredError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetCompleteRequestSchema, PasswordResetRequestSchema, \
    TokenRefreshResponseSchema, TokenRefreshRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema
from schemas.accounts import TokenAccessRefreshResponseSchema, TokenAccessRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = user_group.scalar_one_or_none()
    db_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = db_user.scalar_one_or_none()
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    hashed = hash_password(user.password)
    try:
        new_user = UserModel(email=user.email, _hashed_password=hashed, group=user_group)
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
    return new_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def user_token_activation(user_info: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_info.email))
    db_user = db_user.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    result = await db.execute(select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == db_user.id,
        ActivationTokenModel.token == user_info.token
    ))
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    expires_at = db_token.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True

    await db.delete(db_token)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=PasswordResetCompleteRequestSchema, status_code=200)
async def password_reset(user_info: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_info.email))
    db_user = db_user.scalar_one_or_none()
    if db_user and db_user.is_active:
        result = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
        )
        existing_tokens = result.scalars().all()
        for token in existing_tokens:
            await db.delete(token)

        token = secrets.token_urlsafe(32)
        new_token = PasswordResetTokenModel(user_id=db_user.id,
                                            token=token,
                                            expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        db.add(new_token)
        await db.commit()

    return PasswordResetCompleteRequestSchema(
        message="If you are registered,"
                " you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=TokenRefreshResponseSchema, status_code=200)
async def password_reset_complete(user_info: TokenRefreshRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_info.email))
    db_user = db_user.scalar_one_or_none()
    if db_user:
        result = await db.execute(
            select(PasswordResetTokenModel).where(
                and_(
                    PasswordResetTokenModel.user_id == db_user.id,
                    PasswordResetTokenModel.token == user_info.token
                )
            )
        )
        db_token = result.scalar_one_or_none()
        if not db_token:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == db_user.id
                )
            )
            await db.commit()

            raise HTTPException(status_code=400, detail="Invalid email or token.")
        expires_at = db_token.expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await db.delete(db_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        hashed = hash_password(user_info.password)
        try:
            db_user._hashed_password = hashed
            await db.flush()
            await db.delete(db_token)
            await db.commit()
            await db.refresh(db_user)
        except Exception:
            await db.rollback()
            raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
        return TokenRefreshResponseSchema(message="Password reset successfully.")
    raise HTTPException(status_code=400, detail="Invalid email or token.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(user_info: UserLoginRequestSchema,
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                db: AsyncSession = Depends(get_db),
                settings: BaseAppSettings = Depends(get_settings)):
    db_user = await db.execute(select(UserModel).where(UserModel.email == user_info.email))
    db_user = db_user.scalar_one_or_none()
    if not db_user or not verify_password(user_info.password, db_user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": db_user.id})
        token_obj = RefreshTokenModel.create(user_id=db_user.id,
                                             token=refresh_token,
                                             days_valid=settings.LOGIN_TIME_DAYS)
        db.add(token_obj)
        await db.commit()
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")
    return UserLoginResponseSchema(access_token=access_token,
                                   refresh_token=refresh_token,
                                   token_type="bearer")


@router.post("/refresh/", response_model=TokenAccessRefreshResponseSchema)
async def get_access_token(user_info: TokenAccessRefreshRequestSchema,
                           jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                           db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt_manager.decode_refresh_token(user_info.refresh_token)
    except TokenExpiredError:
        db_token = await db.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.token == user_info.refresh_token)
        )
        db_token = db_token.scalar_one_or_none()
        if db_token:
            await db.delete(db_token)
            await db.commit()

        raise HTTPException(status_code=400, detail="Token has expired.")

    db_token = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == user_info.refresh_token)
    )
    db_token = db_token.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    expires_at = db_token.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Token has expired.")

    db_user = await db.execute(
        select(UserModel).where(UserModel.id == payload["user_id"])
    )
    db_user = db_user.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access = jwt_manager.create_access_token(data={"user_id": db_user.id})
    return TokenAccessRefreshResponseSchema(access_token=new_access)
