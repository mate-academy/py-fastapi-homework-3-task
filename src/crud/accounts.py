from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, UserGroupEnum, UserGroupModel
from schemas import UserRegistrationRequestSchema


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema) -> UserModel:
    group_id = await db.scalar(
        select(UserGroupModel.id)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    db_user = UserModel(
        email=user.email,
        group_id=group_id
    )
    db_user.password = user.password
    db.add(db_user)
    await db.flush()
    return db_user


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    return await db.scalar(select(UserModel).where(UserModel.email == email))
