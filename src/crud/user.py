from datetime import datetime, timezone
from fastapi import HTTPException

from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy import select

from database import UserModel, ActivationTokenModel
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password
import secrets
from sqlalchemy.orm import joinedload


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    db_user = UserModel.create(
        email=user.email,
        raw_password=user.password,
        group_id=1,
    )
    db.add(db_user)
    await db.flush()
    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)

    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def activate_user(db: AsyncSession, email: str, token: str):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == email)
    )
    user = result.unique().scalar_one_or_none()
    if not user:
        raise BaseSecurityError("Invalid or expired activation token.")

    if user.is_active:
        raise BaseSecurityError("User account is already active.")

    activation = user.activation_token
    if not activation:
        raise BaseSecurityError("Invalid or expired activation token.")

    token = token.strip()

    if activation.token != token:
        raise BaseSecurityError("Invalid or expired activation token.")

    now = datetime.now(timezone.utc)
    expires_at = activation.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < now:
        raise BaseSecurityError("Invalid or expired activation token.")

    user.is_active = True
    await db.delete(activation)
    await db.commit()
    await db.refresh(user)

    return user
