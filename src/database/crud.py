from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import UserModel, UserGroupEnum, UserGroupModel, ActivationTokenModel, PasswordResetTokenModel
from schemas import accounts
from security.passwords import hash_password


async def create_user(db: AsyncSession, user: accounts.UserRegistrationRequestSchema):
    hashed = hash_password(user.password)
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = user_group.scalar_one_or_none()
    db_user = UserModel(email=user.email, _hashed_password=hashed, group=user_group)
    db.add(db_user)
    await db.flush()

    db.add(ActivationTokenModel(user_id=db_user.id))

    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def activate_user(db: AsyncSession, payload: accounts.ActivateAccountRequest):
    result = await db.execute(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            UserModel.email == payload.email,
            ActivationTokenModel.token == payload.token,
        )
    )
    return result.scalar_one_or_none()


async def password_reset_token(db: AsyncSession, payload: accounts.PasswordResetRequestSchema):
    result = await db.execute(
        select(PasswordResetTokenModel)
        .join(PasswordResetTokenModel.user)
        .options(joinedload(PasswordResetTokenModel.user))
        .where(UserModel.email == payload.email)
    )
    return result.scalar_one_or_none()
