from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database.models.accounts import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from schemas.accounts import UserRegistrationRequestSchema
from security.passwords import hash_password


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    hashed = hash_password(user.password)

    user_group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = user_group_result.scalar_one_or_none()

    if not user_group:
        raise ValueError("Default user group 'user' not found in the database.")

    db_user = UserModel(email=user.email, _hashed_password=hashed, group_id=user_group.id)
    db.add(db_user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)
    await db.commit()
    await db.refresh(db_user)

    return db_user
