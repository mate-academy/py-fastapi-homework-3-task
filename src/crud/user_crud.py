from datetime import datetime, timedelta, timezone
from typing import cast

from fastapi import HTTPException
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import BaseAppSettings
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas import UserRegistrationRequestSchema


async def create_user(user_data: UserRegistrationRequestSchema, db: AsyncSession):
    try:
        result = await db.execute(
            select(UserGroupModel.id)
            .where(UserGroupModel.name == UserGroupEnum.USER)
        )
        default_group_id = result.scalar_one_or_none()

        db_user = UserModel.create(
            email=cast(str, user_data.email),
            raw_password=user_data.password,
            group_id=default_group_id
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()

        return db_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


async def get_user_by_email(email: EmailStr, db: AsyncSession):
    result = await db.execute(
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token),
            joinedload(UserModel.password_reset_token)
        )
        .where(UserModel.email == email)
    )
    return result.unique().scalar_one_or_none()


async def activate_user(user: UserModel, activation_token: str, db: AsyncSession) -> dict:
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user_token_model = user.activation_token
    if not user_token_model:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token_expires_at = user_token_model.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc) or user_token_model.token != activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(user_token_model)
    await db.commit()
    return {"message": "User account activated successfully."}


async def reset_request_user_password(user: UserModel, db: AsyncSession):
    if user and user.is_active:

        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.flush()

        password_reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(password_reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


async def reset_completion_user_password(user: UserModel, new_password: str, token: str, db: AsyncSession):
    user_token_model = user.password_reset_token
    if not user_token_model:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_expires_at = user_token_model.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc) or user_token_model.token != token:
        await db.delete(user_token_model)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # UserModel.password setter automatically hashes passwords before storing.
    user.password = new_password

    try:
        await db.delete(user_token_model)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}


async def create_user_access_and_refresh_tokens(
        user: UserModel,
        login_password: str,
        db: AsyncSession,
        jwt_manager: JWTAuthManagerInterface,
        settings: BaseAppSettings
):
    if not user.verify_password(login_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    user_sub_data = {"sub": user.email, "user_id": user.id}

    access_token = jwt_manager.create_access_token(
        data=user_sub_data
    )
    refresh_token = jwt_manager.create_refresh_token(
        data=user_sub_data,
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
    )

    refresh_token_model = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )

    try:
        db.add(refresh_token_model)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def create_new_user_access_token(
    refresh_token : str,
    db: AsyncSession,
    jwt_manager: JWTAuthManagerInterface,
):
    try:
        refresh_token_data = jwt_manager.decode_refresh_token(refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(status_code=400, detail=str(error))

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token))
    db_refresh_token_model = result.scalar_one_or_none()

    if not db_refresh_token_model:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id_from_token_data = refresh_token_data.get("user_id", None)
    result = await db.execute(select(UserModel).where(UserModel.id == user_id_from_token_data))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(
        data=refresh_token_data
    )

    return {"access_token": access_token}
