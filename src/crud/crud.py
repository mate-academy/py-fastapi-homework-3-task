import secrets
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.database import PasswordResetTokenModel
from src.database import (
    ActivationTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
)


async def create_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> UserModel:
    user_group = await db.scalar(
        select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )

    if user_group is None:
        raise ValueError("Default user group not found.")

    user = UserModel.create(
        email=email,
        raw_password=password,
        group_id=user_group.id,
    )

    try:
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)

        return user

    except Exception:
        await db.rollback()
        raise


async def activate_user(
    db: AsyncSession,
    email: str,
    token: str,
) -> bool:
    try:
        activation_token = await db.scalar(
            select(ActivationTokenModel)
            .options(selectinload(ActivationTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == email,
                ActivationTokenModel.token == token,
            )
        )

        if activation_token is None:
            return False

        user = activation_token.user

        if user.is_active:
            return False

        expires_at = activation_token.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            return False

        user.is_active = True
        await db.delete(activation_token)
        await db.commit()

        return True

    except Exception:
        await db.rollback()
        raise


async def create_password_reset_token(
    db: AsyncSession,
    user: UserModel,
) -> PasswordResetTokenModel:
    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        token = PasswordResetTokenModel(
            user_id=user.id,
            token=secrets.token_urlsafe(32),
        )

        db.add(token)
        await db.commit()
        await db.refresh(token)

        return token

    except Exception:
        await db.rollback()
        raise


async def reset_password(
    db: AsyncSession,
    email: str,
    token: str,
    new_password: str,
) -> bool:
    try:
        reset_token = await db.scalar(
            select(PasswordResetTokenModel)
            .options(selectinload(PasswordResetTokenModel.user))
            .join(UserModel)
            .where(UserModel.email == email)
        )

        if reset_token is None:
            return False

        if reset_token.token != token:
            await db.delete(reset_token)
            await db.commit()
            return False

        expires_at = reset_token.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            await db.delete(reset_token)
            await db.commit()
            return False

        user = reset_token.user

        if not user.is_active:
            return False

        user.password = new_password

        await db.delete(reset_token)
        await db.commit()

        return True

    except Exception:
        await db.rollback()
        raise
