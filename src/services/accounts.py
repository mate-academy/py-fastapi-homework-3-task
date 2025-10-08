from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, UserGroupEnum, UserGroupModel, ActivationTokenModel
from security.passwords import hash_password


async def get_user_by_email(db: AsyncSession, email: str):
    stmt = select(UserModel).where(UserModel.email == email)
    user = await db.scalar(stmt)

    return user
