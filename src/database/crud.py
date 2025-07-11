from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, ActivationTokenModel
from schemas import UserRegistrationRequestSchema


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    db_user = UserModel.create(email=user.email, raw_password=user.password, group_id=1)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)
    await db.commit()
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
