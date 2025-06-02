from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel


async def get_user_by_email(db: AsyncSession, email: str):
    user = await db.scalar(select(UserModel).where(UserModel.email == email))
    return user
