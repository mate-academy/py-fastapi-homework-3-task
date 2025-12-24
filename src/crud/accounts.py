from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

import schemas
from database import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
)
from security.passwords import hash_password


async def create_user(db: AsyncSession, user: schemas.UserRegistrationRequestSchema):
    hashed = hash_password(user.password)
    group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == "USER"))
    db_user = UserModel(
        email=str(user.email), _hashed_password=hashed, group_id=group.id
    )
    db.add(db_user)
    await db.flush()

    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    return await db.scalar(select(UserModel).where(UserModel.email == email))


async def get_user_by_id(db: AsyncSession, user_id: int):
    return await db.scalar(select(UserModel).where(UserModel.id == user_id))


async def create_activation_token(db: AsyncSession, user_id: int):
    activation_token = ActivationTokenModel(user_id=user_id)
    db.add(activation_token)
    await db.flush()

    return activation_token


async def get_activation_token(db: AsyncSession, token: str):
    return await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.token == token)
    )


async def delete_activation_token(db: AsyncSession, user_id: int):
    await db.execute(
        delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user_id)
    )


async def delete_reset_password_tokens(db: AsyncSession, user_id: int):
    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_id
        )
    )


async def create_reset_password_token(db: AsyncSession, user_id: int):
    token = PasswordResetTokenModel(user_id=user_id)
    db.add(token)
    await db.flush()

    return token


async def get_reset_password_token(db: AsyncSession, token: str):
    return await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.token == token)
    )
