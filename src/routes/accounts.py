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
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema
from schemas.accounts import AccountsErrorSchema, UserActivationRequestSchema, MessageResponseSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, \
    TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from services.accounts import get_user_by_email

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
    responses={
        409: {
            "model": AccountsErrorSchema,
            "description": "A user with the same email already exists."
        },
        500: {
            "model": AccountsErrorSchema,
            "description": "An error occurred during user creation."
        }
    }
)
async def user_register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    user_group_stmt = select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER.value)
    user_group_id = await db.scalar(user_group_stmt)

    try:
        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=user_group_id
        )
        db.add(new_user)
        await db.flush()

        user_token = ActivationTokenModel(user=new_user)
        db.add(user_token)

        await db.commit()
        await db.refresh(new_user)

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    responses={
        400: {
            "model": AccountsErrorSchema,
            "description": "Invalid or expired activation token, or user account is already active."
        }
    }
)
async def user_account_activation(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)

    if not db_user or db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == db_user.id)
    db_token = await db.scalar(stmt_token)

    if (
            not db_token
            or db_token.token != data.token
            or db_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True
    await db.delete(db_token)
    await db.commit()

    return MessageResponseSchema.model_validate({"message": "User account activated successfully."})


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def password_reset_token_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)

    if db_user and db_user.is_active:
        try:
            stmt_delete_token = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
            await db.execute(stmt_delete_token)

            token = PasswordResetTokenModel(user=db_user)

            db.add(token)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()

    return MessageResponseSchema.model_validate(
        {"message": "If you are registered, you will receive an email with instructions."}
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    responses={
        400: {
            "model": AccountsErrorSchema,
            "description": "Invalid email or token."
        },
        500: {
            "model": AccountsErrorSchema,
            "description": "An error occurred while resetting the password."
        }
    }
)
async def password_reset_token_completion(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, data.email)

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    stmt_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
    db_token = await db.scalar(stmt_token)

    if (
            not db_token
            or db_token.token != data.token
            or db_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        if db_token:
            await db.delete(db_token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        db_user.password = data.password
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    await db.delete(db_token)
    await db.commit()

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201,
    responses={
        401: {
            "model": AccountsErrorSchema,
            "description": "Invalid email or password."
        },
        403: {
            "model": AccountsErrorSchema,
            "description": "User account is not activated."
        },
        500: {
            "model": AccountsErrorSchema,
            "description": "An error occurred while processing the request."
        }
    }
)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await get_user_by_email(db, data.email)

    if not db_user or not db_user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    payload = {"user_id": db_user.id}
    access_token = jwt_manager.create_access_token(payload)
    refresh_token = jwt_manager.create_refresh_token(payload)

    try:
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    responses={
        400: {
            "model": AccountsErrorSchema,
            "description": "Token has expired."
        },
        401: {
            "model": AccountsErrorSchema,
            "description": "Refresh token not found."
        },
        404: {
            "model": AccountsErrorSchema,
            "description": "User not found."
        }
    }
)
async def refresh_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        refresh_token = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    db_token = await db.scalar(stmt_token)

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt_user = select(UserModel).where(UserModel.id == refresh_token.get("user_id"))
    db_user = await db.scalar(stmt_user)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    payload = {"user_id": db_user.id}
    new_access_token = jwt_manager.create_access_token(payload)

    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )
