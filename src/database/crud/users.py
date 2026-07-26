from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from database.crud.exceptions import UserAlreadyExistsError, UserNotExistsError, InvalidOrExpiredTokenError
from schemas import UserRegistrationRequestSchema


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
        raise UserNotExistsError(f"A user with email {email} does no exist.")
    if user.is_active:
        raise UserNotExistsError(f"User account is already active.")

    token_stmt = select(ActivationTokenModel).where(ActivationTokenModel.token == token)
    db_token = (await session.execute(token_stmt)).scalar_one_or_none()
    if db_token is None or db_token.expires_at < datetime.now(timezone.utc):
        raise InvalidOrExpiredTokenError("Invalid or expired activation token.")

    user.is_active = True
    await session.delete(db_token)
    await session.commit()
    return user
