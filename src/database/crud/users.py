from datetime import datetime, timezone

from asyncpg import InvalidPasswordError
from fastapi import Depends
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel, PasswordResetTokenModel, \
    RefreshTokenModel
from database.crud.exceptions import (
    UserAlreadyExistsError,
    UserNotExistsError,
    InvalidOrExpiredTokenError,
    UserNotActivatedError,
)
from schemas import UserRegistrationRequestSchema, PasswordResetCompleteRequestSchema, UserLoginRequestSchema
from security.interfaces import JWTAuthManagerInterface


async def create_user(session: AsyncSession, user_data: UserRegistrationRequestSchema) -> UserModel:
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user is not None:
        raise UserAlreadyExistsError(f"A user with this email {user_data.email} already exists.")

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group = (await session.execute(group_stmt)).scalar_one_or_none()
    if group is None:
        raise ValueError("Default user group not found")
    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=group.id,
    )
    token = ActivationTokenModel(user=user)
    session.add(user)
    session.add(token)
    await session.commit()
    await session.refresh(user)
    return user


async def activate_user(session: AsyncSession, email: str, token: str) -> UserModel:
    user_stmt = select(UserModel).where(UserModel.email == email)
    user = (await session.execute(user_stmt)).scalar_one_or_none()
    if user is None:
        raise UserNotExistsError(f"A user with email {email} does not exist.")
    if user.is_active:
        raise UserNotExistsError("User account is already active.")

    token_stmt = select(ActivationTokenModel).where(ActivationTokenModel.token == token)
    db_token = (await session.execute(token_stmt)).scalar_one_or_none()
    if db_token is None or db_token.expires_at < datetime.now(timezone.utc):
        raise InvalidOrExpiredTokenError("Invalid or expired activation token.")

    user.is_active = True
    await session.delete(db_token)
    await session.commit()
    return user


async def create_password_reset_token(session: AsyncSession, email: str) -> bool:
    user_stmt = select(UserModel).where(UserModel.email == email)
    user = (await session.execute(user_stmt)).scalar_one_or_none()
    if user is None or not user.is_active:
        return False
    await session.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

    new_token = PasswordResetTokenModel(user_id=user.id)
    session.add(new_token)

    await session.commit()
    return True


async def complete_password_reset(session: AsyncSession, data: PasswordResetCompleteRequestSchema) -> None:
    user_stmt = (
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )
    user = (await session.execute(user_stmt)).scalar_one_or_none()
    if user is None or not user.is_active:
        raise UserNotExistsError(f"A user with email {data.email} does not exist.")
    token = user.password_reset_token
    if token is None or token.token != data.token:
        raise InvalidOrExpiredTokenError("Invalid email or token.")
    if token.expires_at < datetime.now(timezone.utc):
        await session.delete(token)
        await session.commit()
        raise InvalidOrExpiredTokenError("Invalid email or token.")

    user.password = data.password
    await session.delete(token)
    await session.commit()


async def login(
        session: AsyncSession, data: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface,
        settings: BaseAppSettings
) -> tuple[str, str]:
    user_stmt = (
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )
    user = (await session.execute(user_stmt)).scalar_one_or_none()
    if user is None:
        raise UserNotExistsError(f"A user with email {data.email} does not exist.")
    if not user.is_active:
        raise UserNotActivatedError("User account is not activated.")
    if not user.verify_password(data.password):
        raise InvalidPasswordError("Invalid password.")

    access_token = jwt_manager.create_access_token(data={"sub": user.email})
    refresh_token = jwt_manager.create_refresh_token(data={"sub": user.email})
    refresh_token_db = RefreshTokenModel.create(user.id, settings.LOGIN_TIME_DAYS, refresh_token)

    session.add(refresh_token_db)
    await session.commit()
    return access_token, refresh_token
