from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, UserGroupModel, UserGroupEnum
from schemas import UserRegistrationRequestSchema


class UserAlreadyExistsError(Exception):
    pass


async def create_user(session: AsyncSession, user_data: UserRegistrationRequestSchema) -> UserModel:
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user is not None:
        raise UserAlreadyExistsError(f"A user with this email {user_data.email} already exists.")

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group = (await session.execute(group_stmt)).scalar_one_or_none()
    if group is None:
        raise ValueError("Default user group not found")
    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=group.id,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
