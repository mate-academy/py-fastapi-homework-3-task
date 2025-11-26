from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, cast, delete
from sqlalchemy.orm import selectinload
from src.database.models.accounts import UserModel

from src.config.settings import BaseAppSettings
from src.database.models.accounts import (
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from src.schemas.accounts import (
    UserRegisterRequestSchema,
    UserActivation,
    PasswordResetToken,
    PasswordResetCompletion,
    LoginRequestSchema,
    LoginRequestResponseSchema,
    RefreshAccessRequestSchema,
    UserRegisterResponseSchema,
)
from src.security.interfaces import JWTAuthManagerInterface
from src.security.passwords import hash_password, verify_password
import secrets


async def create_user(db: AsyncSession, user: UserRegisterRequestSchema):
    try:
        hashed = hash_password(user.password)
        db_user = UserModel(
            email=user.email,
            hashed_password=hashed,
            group=UserGroupEnum.USER
        )
        db.add(db_user)
        await db.flush()
        activation_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        token = ActivationTokenModel(
            token=activation_token,
            expires_at=expires_at,
            user_id=cast(int, db_user.id)
        )
        db.add(token)
        await db.commit()
        await db.refresh(db_user)
        return UserRegisterResponseSchema(
            id=db_user.id,
            email=db_user.email,
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occured during user creation."
        )


async def activate_user(db: AsyncSession, data: UserActivation):
    result = await db.execute(select(ActivationTokenModel).where(
        ActivationTokenModel.token == data.token
    ).options(selectinload(ActivationTokenModel.user))
    )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    user = token.user
    if user.email != data.email:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.is_active:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=400, detail="User account is already active."
        )
    user.is_active = True
    await db.delete(token)
    await db.commit()
    await db.refresh(user)
    return {"message": "User account activated successfully."}


async def reset_password_token(db: AsyncSession, data: PasswordResetToken):
    user = get_user_by_email(db, email=data.email)
    token = secrets.token_urlsafe(32)
    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id)
        )
        db.add(PasswordResetTokenModel(
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            user_id=cast(int, user.id)
        )
        )
        await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}


async def reset_password_completion(db: AsyncSession, data: PasswordResetCompletion):
    try:
        result = await db.execute(select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == data.token
        ).options(selectinload(PasswordResetTokenModel.user))
        )
        token = result.scalar_one_or_none()
        if token is None:
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )
        user = token.user
        if not user or not user.is_active or user.email != data.email:
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )
        if cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            await db.delete(token)
            await db.commit()
            raise HTTPException(
                status_code=400, detail="Invalid email or token."
            )
        hashed = hash_password(data.password)
        user.password = hashed
        await db.delete(token)
        await db.commit()
        await db.refresh(user)
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )


async def login_user(db: AsyncSession,
                     data: LoginRequestSchema,
                     jwt_manager: JWTAuthManagerInterface,
                     settings: BaseAppSettings
                     ):
    try:
        user = await get_user_by_email(db, data.email)
        if not user or not verify_password(data.password, user.password):
            raise HTTPException(
                status_code=401, detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403, detail="User account is not activated."
            )

        access_token = jwt_manager.create_access_token(data={"sub": user.email})
        refresh_token = jwt_manager.create_refresh_token(data={"sub": user.email})

        refresh_token_instance = RefreshTokenModel(
            token=refresh_token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.LOGIN_TIME_DAYS),
            user_id=cast(int, user.id)
        )
        db.add(refresh_token_instance)
        await db.commit()
        await db.refresh(user)
        return LoginRequestResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )


async def access_token_refresh(
        db: AsyncSession,
        data: RefreshAccessRequestSchema,
        jwt_manager: JWTAuthManagerInterface
):
    try:
        jwt_manager.decode_refresh_token(data.refresh_token)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")
    result = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    ).options(selectinload(RefreshTokenModel.user)))
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=400, detail="Refresh token not found.")
    user = token.user
    if cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Token has expired.")
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"sub": user.email})

    return {"access_token": new_access_token}


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
