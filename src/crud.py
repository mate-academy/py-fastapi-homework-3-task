from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserModel, UserGroupEnum, UserGroupModel
from schemas.accounts import CreateUser

from security.passwords import hash_password


async def create_user(db: AsyncSession, user: CreateUser):
    hashed = hash_password(user.password)
    result = await db.execute(
        select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER.value
        )
    )
    group = result.scalar_one()
    db_user = UserModel(
        email=user.email, _hashed_password=hashed, group_id=group.id
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    return result.scalar_one_or_none()
