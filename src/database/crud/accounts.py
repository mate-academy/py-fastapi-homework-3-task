from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import ActivationTokenModel
from database.models.accounts import UserModel, UserGroupEnum, UserGroupModel
from database.validators.accounts import validate_email, validate_password_strength
from schemas.accounts import UserRegistrationRequestSchema
from security.passwords import hash_password


async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession) -> UserModel:

    try:
        password = validate_password_strength(user.password)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    hashed_password = hash_password(password)

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = result.scalar_one_or_none()

    email = validate_email(user.email)

    db_user = UserModel(
        email=email,
        _hashed_password=hashed_password,
        group=group,

    )

    activation_token = ActivationTokenModel(
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        user=db_user,
    )

    db.add(db_user)
    db.add(activation_token)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[UserModel]:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
