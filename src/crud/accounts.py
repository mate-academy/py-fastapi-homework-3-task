from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models.accounts import UserGroupEnum, UserGroupModel, UserModel
from schemas.accounts import UserCreate
from security.passwords import hash_password


async def create_user(db: AsyncSession, user: UserCreate):
    res_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER.value)
    )
    group_obj = res_group.scalar_one()
    db_user = UserModel(
        email=user.email, _hashed_password=hash_password(user.password), group=group_obj
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
