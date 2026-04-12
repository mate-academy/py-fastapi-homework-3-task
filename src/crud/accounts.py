from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from security.passwords import hash_password


async def create_user(db: AsyncSession, email: str, password: str) -> UserModel:
    try:
        group_query = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = group_query.scalar_one()
        db_user = UserModel.create(
            email=email,
            raw_password=password,
            group_id=group.id
        )
        db.add(db_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except Exception:
        await db.rollback()
        raise


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def get_activation_token(db: AsyncSession, user_id: int):
    query = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user_id)
    result = await db.execute(query)

    return result.scalar_one_or_none()
