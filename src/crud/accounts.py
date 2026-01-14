from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import Mapped

from database.models.accounts import UserModel, UserGroupModel
from schemas.accounts import UserRegistrationRequestSchema

from security.passwords import hash_password


async def hash_user_password(
        db: AsyncSession,
        user: UserRegistrationRequestSchema,
        group: UserGroupModel
) -> UserModel:
    hashed = hash_password(user.password)
    db_user = UserModel(email=str(user.email), _hashed_password=hashed, group=group)
    return db_user


async def get_user_by_email(db: AsyncSession, email : str) -> UserModel:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
