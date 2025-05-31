from datetime import datetime, timezone
from typing import cast

from fastapi import HTTPException, Depends
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from starlette import status

from config import BaseAppSettings, get_settings, get_jwt_auth_manager
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface


async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession) -> UserRegistrationResponseSchema:
    existing_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
    if existing_user.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    group_result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    group = group_result.scalars().first()
    if not group:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Default user group not found.")

    try:
        new_user = UserModel.create(email=str(user.email), raw_password=user.password, group_id=group.id)
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        ) from e

    return UserRegistrationResponseSchema.model_validate(new_user)


async def activate_account(db: AsyncSession, user_data: UserActivationRequestSchema) -> MessageResponseSchema:
    query_result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(UserModel.email == user_data.email, ActivationTokenModel.token == user_data.token)
    )
    token_record = query_result.scalars().first()

    now_utc = datetime.now(timezone.utc)
    if not token_record or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < now_utc:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    user = token_record.user
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


async def reset_password(db: AsyncSession, user_data: PasswordResetRequestSchema) -> MessageResponseSchema:
    stmt = select(UserModel).filter_by(email=user_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")

    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


async def complete_reset_password(db: AsyncSession, user_data: PasswordResetCompleteRequestSchema) -> MessageResponseSchema:
    result = await db.execute(select(UserModel).filter_by(email=user_data.email))
    user = result.scalars().first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    result = await db.execute(select(PasswordResetTokenModel).filter_by(user_id=user.id))
    token_record = result.scalars().first()

    if not token_record or token_record.token != user_data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user.password = user_data.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


async def login(
    db: AsyncSession,
    data: UserLoginRequestSchema,
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> UserLoginResponseSchema:
    result = await db.execute(select(UserModel).filter_by(email=data.email))
    user = result.scalars().first()

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=jwt_refresh_token
        )
        db.add(refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while processing the request.")

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return UserLoginResponseSchema(access_token=jwt_access_token, refresh_token=jwt_refresh_token)


async def refresh(
    db: AsyncSession,
    token: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        decoded_token = jwt_manager.decode_refresh_token(token.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    stmt = select(RefreshTokenModel).filter_by(token=token.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()
    if not refresh_token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    stmt = select(UserModel).filter_by(id=user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=new_access_token)
