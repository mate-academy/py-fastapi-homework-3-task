from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    hashed = hash_password(user.password)
    db_user = UserModel(email=user.email, _hashed_password=hashed)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user
