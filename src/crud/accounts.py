from jose import ExpiredSignatureError
from sqlalchemy.exc import SQLAlchemyError

from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationRequestSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequestSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy import select, delete
from security.passwords import hash_password


async def create_user_with_hash_password(
    db: AsyncSession,
    user_data: UserRegistrationRequestSchema
):
    try:
        if await db.scalar(select(UserModel).where(UserModel.email == user_data.email)):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User group not found."
            )

        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add_all([user, ActivationTokenModel(user=user)])
        await db.commit()

        await db.refresh(user)

        return user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


async def activate_user_account(db: AsyncSession, email: str, token: str):
    stmt = (
        select(ActivationTokenModel)
        .join(UserModel)
        .where(UserModel.email == email, ActivationTokenModel.token == token)
    )
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user_result = await db.execute(select(UserModel).where(UserModel.id == token_record.user_id))
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


async def reset_password(db: AsyncSession, user_data: PasswordResetCompleteRequestSchema):
    try:
        stmt = (
            select(PasswordResetTokenModel)
            .join(UserModel)
            .where(
                UserModel.email == user_data.email,
                PasswordResetTokenModel.token == user_data.token
            )
        )
        result = await db.execute(stmt)
        token_record = result.scalars().first()

        if not token_record:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user.has(email=user_data.email)
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user_result = await db.execute(select(UserModel).where(UserModel.id == token_record.user_id))
        user = user_result.scalars().first()

        if not user or not user.is_active:
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = user_data.password
        db.add(user)

        await db.delete(token_record)
        await db.commit()
        await db.refresh(user)
        db.expire_all()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


async def request_password_reset_token(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession
):
    try:
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        existing_user = await db.execute(stmt)
        user = existing_user.scalars().first()

        if not user or not user.is_active:
            return {
                "message": "If you are registered, you will receive an email with instructions."
            }

        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        new_token = PasswordResetTokenModel(user_id=int(user.id))
        db.add(new_token)

        await db.commit()
        await db.refresh(new_token)

        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )



async def login_logic(
    user_data: UserLoginRequestSchema,
    db: AsyncSession,
    jwt_manager: JWTAuthManagerInterface,
    settings: BaseAppSettings
):
    try:
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        existing_user = await db.execute(stmt)
        user = existing_user.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        verify_password = user.verify_password(user_data.password)
        if not verify_password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_record = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_record)

        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


async def refresh_token_logic(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession,
        jwt_manager: JWTAuthManagerInterface
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = payload.get("user_id")

        stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
        result = await db.execute(stmt)
        token_record = result.scalars().first()

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        stmt_user = select(UserModel).where(UserModel.id == user_id)
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token({"user_id": user.id})

        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }

    except (ExpiredSignatureError, TokenExpiredError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token."
        )
