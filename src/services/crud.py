from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
)
from schemas.accounts import UserRegistrationRequestSchema


async def get_group_by_name(
    db: AsyncSession,
    name: UserGroupEnum,
) -> UserGroupModel | None:
    return await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == name)
    )


async def get_user_by_email(
    db: AsyncSession,
    email: str,
) -> UserModel | None:
    return await db.scalar(
        select(UserModel).where(UserModel.email == email.lower())
    )


async def get_user_by_id(
    db: AsyncSession,
    user_id: int,
) -> UserModel | None:
    return await db.scalar(
        select(UserModel).where(UserModel.id == user_id)
    )


async def create_user(
    db: AsyncSession,
    user_data: UserRegistrationRequestSchema,
    group_id: int,
) -> UserModel:
    db_user = UserModel.create(
        email=str(user_data.email),
        raw_password=user_data.password,
        group_id=group_id,
    )

    db.add(db_user)
    return db_user


async def get_activation_token(
    db: AsyncSession,
    token: str,
) -> ActivationTokenModel | None:
    return await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == token
        )
    )


def activate_user(user: UserModel) -> None:
    user.is_active = True


async def delete_activation_token(
    db: AsyncSession,
    token: ActivationTokenModel,
) -> None:
    await db.delete(token)


async def delete_password_reset_tokens(
    db: AsyncSession,
    user_id: int,
) -> None:
    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_id
        )
    )


def create_password_reset_token(
    db: AsyncSession,
    user: UserModel,
) -> PasswordResetTokenModel:
    token = PasswordResetTokenModel(user=user)
    db.add(token)

    return token


async def get_password_reset_token_by_user_id(
    db: AsyncSession,
    user_id: int,
) -> PasswordResetTokenModel | None:
    return await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_id
        )
    )


async def delete_password_reset_token(
    db: AsyncSession,
    token: PasswordResetTokenModel,
) -> None:
    await db.delete(token)


async def get_user_by_email_and_password(
    db: AsyncSession,
    email: str,
    password: str,
) -> UserModel | None:
    user = await get_user_by_email(
        db=db,
        email=email,
    )

    if user is None or not user.verify_password(
        raw_password=password
    ):
        return None

    return user


def create_refresh_token(
    db: AsyncSession,
    user_id: int,
    days_valid: int,
    token: str,
) -> RefreshTokenModel:
    refresh_token_record = RefreshTokenModel.create(
        user_id=user_id,
        days_valid=days_valid,
        token=token,
    )

    db.add(refresh_token_record)
    return refresh_token_record


async def get_refresh_token(
    db: AsyncSession,
    refresh_token: str,
) -> RefreshTokenModel | None:
    return await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token
        )
    )
