from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
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

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    existing_stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(existing_stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        # Ensure default user group exists (tests seed it)
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        user_group = group_result.scalars().first()
        if not user_group:
            raise HTTPException(status_code=500, detail="An error occurred during user creation.")

        user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=user_group.id)
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()
        return UserRegistrationResponseSchema(id=cast(int, user.id), email=user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate user account",
)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    # Find the user by email
    user_stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        # Generic invalid token response
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    # Fetch token record by token value
    token_stmt = select(ActivationTokenModel).where(ActivationTokenModel.token == activation_data.token)
    token_result = await db.execute(token_stmt)
    token_record = token_result.scalars().first()

    if not token_record or token_record.user_id != user.id:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.id == token_record.id))
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request password reset token",
)
async def request_password_reset_token(
        reset_request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    # Always return generic message
    generic_message = {"message": "If you are registered, you will receive an email with instructions."}

    user_stmt = select(UserModel).where(UserModel.email == reset_request.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.is_active:
        return MessageResponseSchema(**generic_message)

    # Optionally remove old token for the user to keep one active token
    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

    token_record = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(token_record)
    await db.commit()
    return MessageResponseSchema(**generic_message)


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
)
async def reset_password_complete(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user_stmt = select(UserModel).where(UserModel.email == reset_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_stmt = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    token_result = await db.execute(token_stmt)
    token_record = token_result.scalars().first()

    if not token_record or token_record.token != reset_data.token:
        if token_record:
            await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id))
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id))
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = reset_data.password
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Login user",
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    user_stmt = select(UserModel).where(UserModel.email == login_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})
    refresh_token = jwt_manager.create_refresh_token({"user_id": cast(int, user.id)})

    refresh_token_record = RefreshTokenModel.create(
        user_id=cast(int, user.id),
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )
    try:
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh access token",
)
async def refresh_access_token(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        token_data = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Ensure token exists in DB
    token_stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
    token_result = await db.execute(token_stmt)
    token_record = token_result.scalars().first()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = token_data.get("user_id")
    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})
    return TokenRefreshResponseSchema(access_token=access_token)
