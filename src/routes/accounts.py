import os

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
from database.crud.accounts import get_user_by_email, create_user
from exceptions import BaseSecurityError, InvalidTokenError, TokenExpiredError
from schemas.accounts import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password, hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    try:
        user = await create_user(user=user, db=db)
        return UserRegistrationResponseSchema(id=user.id, email=user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def account_activation(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user_data.email)

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    token = token_result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)

    if expires_at < now_utc:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True

    await db.delete(token)
    await db.flush()
    await db.commit()
    return MessageResponseSchema(
        message="User account activated successfully.",
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def password_reset_token_request(reset_request: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, reset_request.email)

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        new_reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(new_reset_token)
        await db.flush()
        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, reset_data.email)

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
        .where(PasswordResetTokenModel.token == reset_data.token)
    )
    token = token_result.scalar_one_or_none()

    if not token:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)

    if expires_at < now_utc:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        hashed_new_password = hash_password(reset_data.password)
        user._hashed_password = hashed_new_password
        await db.delete(token)
        await db.flush()
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await get_user_by_email(db, user_data.email)

    if not user or not verify_password(user_data.password, cast(str, user._hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        data_for_token = {
            "user_id": user.id,
            "email": user.email,
        }

        access_token = jwt_manager.create_access_token(data=data_for_token)

        create_refresh_token = jwt_manager.create_refresh_token(data=data_for_token)
        assign_refresh_token = RefreshTokenModel(
            user_id=cast(int, user.id),
            token=create_refresh_token,
        )

        db.add(assign_refresh_token)
        await db.commit()
        await db.refresh(user)
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=create_refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def token_refresh(
        provided_token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        jwt_manager.decode_refresh_token(provided_token.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        )

    token_result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == provided_token.refresh_token)
    )
    refresh_token = token_result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(select(UserModel).where(UserModel.id == refresh_token.user_id))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
