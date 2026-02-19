from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import (
    ActivationTokenModel,
    UserModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from schemas import UserRegistrationRequestSchema


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    try:
        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=1,
        )

        db.add(db_user)
        await db.flush()
        db_user.activation_token = ActivationTokenModel()

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    stmt = (
        select(UserModel)
        .options(
            selectinload(UserModel.activation_token),
            selectinload(UserModel.password_reset_token),
        )
        .where(UserModel.email == email)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def delete_activation_token(db: AsyncSession, token: ActivationTokenModel):
    await db.delete(token)
    await db.commit()


async def validate_activation_token(user: UserModel, token: str):
    if not user.activation_token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.activation_token.expires_at.tzinfo is None:
        user.activation_token.expires_at = user.activation_token.expires_at.replace(
            tzinfo=timezone.utc
        )
    return (user.activation_token.token == token) and (
        user.activation_token.expires_at > datetime.now(timezone.utc)
    )


async def check_and_change_user_status(db: AsyncSession, user: UserModel):
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    user.is_active = True

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def delete_password_reset_token(db: AsyncSession, user: UserModel):
    await db.delete(user.password_reset_token)
    await db.commit()
    await db.refresh(user)


async def create_password_reset_token(db: AsyncSession, user: UserModel):
    await db.refresh(user)
    user.password_reset_token = PasswordResetTokenModel()

    db.add(user)
    await db.commit()
    await db.refresh(user, attribute_names=["password_reset_token"])
    return user


async def validate_reset_token(user: UserModel, token: str):
    if not user.password_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if user.password_reset_token.expires_at.tzinfo is None:
        user.password_reset_token.expires_at = (
            user.password_reset_token.expires_at.replace(tzinfo=timezone.utc)
        )
    return (user.password_reset_token.token == token) and (
        user.password_reset_token.expires_at > datetime.now(timezone.utc)
    )


async def update_user_password(db: AsyncSession, user: UserModel, password: str):
    user.password = password

    db.add(user)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )
    await db.refresh(user)
    return user


async def create_refresh_token(
    db: AsyncSession, user_id: int, token: str, days_valid: int
):
    new_refresh_token = RefreshTokenModel.create(
        user_id=user_id, token=token, days_valid=days_valid
    )

    db.add(new_refresh_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )
    await db.refresh(new_refresh_token)
    return new_refresh_token


async def check_exist_refresh_token_in_db(db: AsyncSession, refresh_token: str):
    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int):
    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
