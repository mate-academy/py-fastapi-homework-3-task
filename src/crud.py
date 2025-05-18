from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from database import UserModel, UserGroupEnum, UserGroupModel, ActivationTokenModel
from database.models.accounts import PasswordResetTokenModel
from schemas import UserRegistrationRequestSchema
from security.passwords import hash_password
from fastapi import HTTPException


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    default_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER.name)
    )
    group = default_group.scalar_one_or_none()

    if not group:
        raise HTTPException(status_code=400, detail="Default user group not found")

    hashed = hash_password(user.password)
    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed,
        group_id=group.id
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)
    await db.commit()
    await db.refresh(activation_token)

    response_data = {
        "id": db_user.id,
        "email": db_user.email,
        "group_id": db_user.group_id,
        "activation_token": activation_token.token
    }

    return response_data


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


async def activate_token(activation_token: str, email: str, db: AsyncSession):
    user_query = select(UserModel).where(UserModel.email == email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        return "invalid_token"

    if user.is_active:
        return "already_active"

    token_query = (
        select(ActivationTokenModel)
        .where(
            ActivationTokenModel.token == activation_token,
            ActivationTokenModel.user_id == user.id
        )
    )
    token_result = await db.execute(token_query)
    token_instance = token_result.scalar_one_or_none()

    if not token_instance:
        return "invalid_token"

    if token_instance.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    db.add(user)
    await db.delete(token_instance)
    await db.commit()

    return True


async def password_reset(email, db: AsyncSession):
    user_query = select(UserModel).where(UserModel.email == email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    token_query = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    token_result = await db.execute(token_query)
    existing_token = token_result.scalar_one_or_none()

    if existing_token:
        await db.delete(existing_token)
        await db.commit()

    reset_token = PasswordResetTokenModel(user_id=user.id)

    db.add(reset_token)
    await db.commit()
    await db.refresh(reset_token)

    return True


async def password_reset_complete(email, token, password, db: AsyncSession):
    try:
        user_query = select(UserModel).where(UserModel.email == email, UserModel.is_active.is_(True))
        user_result = await db.execute(user_query)
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_query = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == token,
        )
        token_result = await db.execute(token_query)
        existing_token = token_result.scalar_one_or_none()
        if not existing_token:
            all_tokens_query = select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            all_tokens_result = await db.execute(all_tokens_query)
            all_tokens = all_tokens_result.scalars().all()
            for token_to_delete in all_tokens:
                await db.delete(token_to_delete)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_expires_at = existing_token.expires_at
        if token_expires_at.tzinfo is None:
            token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

        if token_expires_at < datetime.now(timezone.utc):
            await db.delete(existing_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user._hashed_password = hash_password(password)
        db.add(user)

        await db.delete(existing_token)
        await db.commit()
        await db.refresh(user)

        return True
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
