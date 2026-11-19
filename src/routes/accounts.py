import os
from datetime import datetime, timezone, timedelta
from typing import cast
from urllib import response

from fastapi import APIRouter, Depends, status, HTTPException, Query
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import create_user, get_user_by_email, activate_user, set_reset_token, reset_password, user_login, \
    refresh_access_token
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
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema
from schemas.accounts import Token, UserLoginRequestSchema, UserLoginResponseSchema, UserAllSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    TokenRefreshRequestSchema, TokenRefreshResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    description="Register a new user",
    status_code=status.HTTP_201_CREATED
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):

    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {db_user.email} already exists."
        )

    try:
        return await create_user(db, user)
    except (SQLAlchemyError, ValueError):
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.get("/me/", response_model=UserAllSchema)
async def get_user(
    email: str,
    db: AsyncSession = Depends(get_db),
):
    db_user = await get_user_by_email(db=db, email=email.lower())
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    return db_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
        user: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    await activate_user(db, user)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    await set_reset_token(db, data)
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def finish_password_reset(
    user: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    await reset_password(db, user)
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    return await user_login(
        db=db,
        data=data,
        jwt_manager=jwt_manager,
        login_time_days=settings.LOGIN_TIME_DAYS,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    return await refresh_access_token(db=db, data=data, jwt_manager=jwt_manager)
