from sqlalchemy.ext.asyncio import AsyncSession
from database.models.accounts import UserModel
from schemas import UserCreate
from security import hash_password

async def create_user(db: AsyncSession, user: UserCreate):
    hashed = hash_password(user.password)
    db_user = User(email=user.email, hashed_password=hashed, role=user.role)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()
