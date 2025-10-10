from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database.models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    result = await db.execute(select(UserModel).where(UserModel.email == email.lower()))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int) -> UserModel | None:
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    return result.scalar_one_or_none()


async def get_user_with_activation_token(db: AsyncSession, email: str) -> UserModel | None:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == email.lower())
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_user_group_by_name(db: AsyncSession, group_name: UserGroupEnum) -> UserGroupModel | None:
    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == group_name))
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, email: str, raw_password: str, group_id: int) -> UserModel:
    new_user = UserModel.create(
        email=email.lower(),
        raw_password=raw_password,
        group_id=group_id
    )
    db.add(new_user)
    await db.flush()
    return new_user


async def get_password_reset_token(db: AsyncSession, user_id: int) -> PasswordResetTokenModel | None:
    result = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_id)
    )
    return result.scalar_one_or_none()


async def get_refresh_token(db: AsyncSession, token: str) -> RefreshTokenModel | None:
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == token))
    return result.scalar_one_or_none()
