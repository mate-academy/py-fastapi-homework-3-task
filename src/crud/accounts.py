import os
from datetime import timedelta, datetime, timezone
from secrets import compare_digest

from fastapi import HTTPException, Depends
from starlette import status

from config import get_jwt_auth_manager
from database import UserModel, UserGroupModel, ActivationTokenModel, UserGroupEnum, PasswordResetTokenModel, \
    RefreshTokenModel
from database.validators.accounts import validate_password_strength, validate_email
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserLoginRequestSchema, UserActivationRequestSchema, \
    PasswordResetCompleteRequestSchema, PasswordResetRequestSchema, TokenRefreshRequestSchema

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

access_token_expires = timedelta(minutes=30)
refresh_token_expires = timedelta(days=1)


async def get_user_group_id(db: AsyncSession) -> int | None:
    result = await db.execute(
        select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    group_id = await get_user_group_id(db=db)
    if group_id is None:
        raise ValueError("Default user group not found.")

    db_user = UserModel.create(email=user.email, raw_password=user.password, group_id=group_id)
    db_user.activation_token = ActivationTokenModel()

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(
        select(UserModel)
        .options(
            selectinload(UserModel.activation_token),
            selectinload(UserModel.password_reset_token),
        )
        .where(UserModel.email == email)
    )
    return result.scalar_one_or_none()


def _is_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


async def activate_user(db: AsyncSession, data: UserActivationRequestSchema):
    invalid_token_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired activation token."
    )

    db_user = await get_user_by_email(db=db, email=data.email.lower())
    if db_user is None:
        raise invalid_token_error

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token = db_user.activation_token
    if (
        token is None
        or not compare_digest(token.token, data.token)
        or _is_expired(token.expires_at)
    ):
        raise invalid_token_error

    db_user.is_active = True
    await db.delete(token)
    await db.commit()
    return db_user


async def set_reset_token(
    db: AsyncSession,
    data: PasswordResetRequestSchema,
) -> None:
    db_user = await get_user_by_email(db=db, email=data.email.lower())
    if db_user is None or not db_user.is_active:
        return

    if db_user.password_reset_token is not None:
        await db.delete(db_user.password_reset_token)
        await db.flush()

    db_user.password_reset_token = PasswordResetTokenModel()
    await db.commit()


async def reset_password(
        db: AsyncSession,
        data: PasswordResetCompleteRequestSchema,
):
    invalid_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token."
    )

    db_user = await get_user_by_email(db=db, email=data.email.lower())
    if db_user is None or not db_user.is_active:
        raise invalid_error

    token = db_user.password_reset_token
    if token is None:
        raise invalid_error

    if not compare_digest(token.token, data.token) or _is_expired(token.expires_at):
        await db.delete(token)
        await db.commit()
        raise invalid_error

    try:
        db_user.password = data.password
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return db_user


async def user_login(
        db: AsyncSession,
        data: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface,
        login_time_days: int,
):
    db_user = await get_user_by_email(db, data.email.lower())

    if db_user is None or not db_user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})

    try:
        db.add(RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=login_time_days,
            token=refresh_token,
        ))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    access_token = jwt_manager.create_access_token({"user_id": db_user.id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def refresh_access_token(
        db: AsyncSession,
        data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface,
) -> dict:

    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        )

    user_id = payload.get("user_id")

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    token_record = result.scalar_one_or_none()
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if token_record.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    return {"access_token": jwt_manager.create_access_token({"user_id": user_id})}
