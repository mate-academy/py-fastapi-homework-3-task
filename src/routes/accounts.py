import os
from datetime import datetime, timezone, timedelta
from typing import cast, List

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from security.token_manager import JWTAuthManager

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud import create_user, get_user_by_email
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
    UserRead,
    CreateUser,
    TokenActivate,
    TokenPasswordRefresh,
    ResetPassword,
    LoginSchema,
    LoginResponseSchema,
    TokenRefresh,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token
from service import remove_token, get_jwt_manager

router = APIRouter()


@router.post("/register/", response_model=UserRead, status_code=201)
async def register(user: CreateUser, db: AsyncSession = Depends(get_db)):
    try:
        db_user = await get_user_by_email(db, user.email)
        if db_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user.email} already exists.",
            )
        new_user = await create_user(db, user)
        new_token = ActivationTokenModel(user_id=new_user.id)
        db.add(new_token)
        await db.commit()
        await db.refresh(new_token)

        return new_user

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=dict)
async def activate(model: TokenActivate, db: AsyncSession = Depends(get_db)):
    user_status = await get_user_by_email(db, model.email)
    if user_status.is_active:
        raise HTTPException(
            status_code=400, detail="User account is already active."
        )
    user_token = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == model.token
        )
    )
    db_token = user_token.scalar_one_or_none()
    if db_token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    expires_at = cast(datetime, db_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    user_status.is_active = True
    await db.flush()
    await db.refresh(user_status)
    await db.delete(db_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=dict)
async def password_reset_token(
    model: TokenPasswordRefresh, db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, model.email)
    if user and user.is_active:
        old_tokens = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        for token in old_tokens.scalars().all():
            await db.delete(token)
        await db.commit()
        new_refresh_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_refresh_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=dict)
async def password_reset_compleat(
    model: ResetPassword, db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_user_by_email(db, model.email)
        check_token = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.token == model.token
            )
        )
        if user is None:
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )
        db_check_token = check_token.scalar_one_or_none()
        if db_check_token is None:
            await remove_token(db, user)
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )

        expires_at = cast(datetime, db_check_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        if expires_at < datetime.now(timezone.utc):
            await remove_token(db, user)
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )
        await db.delete(db_check_token)
        new_pass = hash_password(model.password)
        user._hashed_password = new_pass
        await db.commit()
        await db.refresh(user)

        return {"message": "Password reset successfully."}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=LoginResponseSchema, status_code=201)
async def login(
    model: LoginSchema,
    db: AsyncSession = Depends(get_db),
    jwt_create: JWTAuthManager = Depends(get_jwt_manager),
):
    try:
        user_auth = await db.execute(
            select(UserModel).where(UserModel.email == model.email)
        )
        user = user_auth.scalar_one_or_none()
        if user is None:
            raise HTTPException(
                status_code=401, detail="Invalid email or password."
            )
        password_verification = verify_password(
            model.password, user._hashed_password
        )
        if not password_verification:
            raise HTTPException(
                status_code=401, detail="Invalid email or password."
            )
        if not user.is_active:
            raise HTTPException(
                status_code=403, detail="User account is not activated."
            )

        token_data = {"user_id": user.id}
        access = jwt_create.create_access_token(token_data)
        refresh = jwt_create.create_refresh_token(token_data)
        new_refresh_token = RefreshTokenModel(token=refresh, user_id=user.id)
        db.add(new_refresh_token)
        await db.commit()
        await db.refresh(new_refresh_token)

        return LoginResponseSchema(
            access_token=access, refresh_token=refresh, token_type="bearer"
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/", response_model=dict)
async def get_new_token(
    model: TokenRefresh,
    db: AsyncSession = Depends(get_db),
    jwt_create: JWTAuthManager = Depends(get_jwt_manager),
):
    try:
        decode_token = jwt_create.decode_refresh_token(model.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    to_check_in_db = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == model.refresh_token
        )
    )
    check_token = to_check_in_db.scalar_one_or_none()
    if check_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_id = decode_token.get("user_id")
    to_find_user = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    check_user = to_find_user.scalar_one_or_none()
    if check_user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    token_data = {"user_id": user_id}
    new_token = jwt_create.create_access_token(token_data)
    return {"access_token": new_token}
