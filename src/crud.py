from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.database import UserModel
from src.security.passwords import hash_password
from src.schemas.accounts import UserCreate


async def create_user(db: AsyncSession, user: UserCreate):
    hashed = hash_password(user.password)
    db_user = UserModel(email=user.email, hashed_password=hashed, role=user.role)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
