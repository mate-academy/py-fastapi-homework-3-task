from datetime import datetime, timezone, timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database.models.accounts import UserModel, UserGroupEnum, UserGroupModel
from schemas.accounts import UserRegistrationRequestSchema

from security.passwords import hash_password


async def get_user_group_by_name(db: AsyncSession, name: UserGroupEnum) -> UserGroupModel:
    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == name)
    )
    group = result.scalar_one()
    return group


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    hashed = hash_password(user.password)
    user_group = await get_user_group_by_name(db, UserGroupEnum.USER)

    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed,
        group_id=user_group.id
    )
    db.add(db_user)
    try:
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return db_user


async def get_user_by_id(db: AsyncSession, user_id: int):
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def get_active_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(
        select(UserModel).where(UserModel.email == email, UserModel.is_active.is_(True))
    )
    return result.scalar_one_or_none()


async def activate_user_account(db: AsyncSession, user: UserModel):
    user.is_active = True
    await db.commit()


async def create_activation_token(db: AsyncSession, user: UserModel):
    token = str(uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    activation_token = ActivationTokenModel(
        user_id=user.id,
        token=token,
        expires_at=expires_at
    )
    db.add(activation_token)
    await db.commit()


async def get_user_token_by_email_and_token(db: AsyncSession, token_model, email: str, token: str):
    result = await db.execute(
        select(token_model)
        .options(selectinload(token_model.user))
        .join(UserModel)
        .where(
            UserModel.email == email,
            token_model.token == token
        )
    )
    return result.scalar_one_or_none()


async def delete_activation_token(db: AsyncSession, token: ActivationTokenModel):
    await db.delete(token)
    await db.commit()


async def delete_existing_password_reset_tokens(db: AsyncSession, user: UserModel):
    result = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    tokens = result.scalars().all()
    for token in tokens:
        db.delete(token)
    await db.commit()


async def create_password_reset_token(db: AsyncSession, user: UserModel, token: str):
    token_obj = PasswordResetTokenModel(user_id=user.id, token=token)
    db.add(token_obj)
    await db.commit()


async def delete_password_reset_token(db: AsyncSession, token_obj: PasswordResetTokenModel):
    await db.delete(token_obj)
    await db.commit()


async def update_user_password(db: AsyncSession, user: UserModel, new_password: str):
    hashed = hash_password(new_password)
    user._hashed_password = hashed
    try:
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


async def get_refresh_token_by_token(db: AsyncSession, token: str):
    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token)
    )
    return result.scalar_one_or_none()
