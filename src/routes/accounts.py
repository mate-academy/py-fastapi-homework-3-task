from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
            "<h3>This endpoint allows clients to register a new user. "
            "It accepts an email and password. A new activation token is created, "
            "and the user is assigned to the default user group.</h3>"
    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "A user with this email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email test@example.com already exists."}
                }
            },
        },
        500: {
            "description": "An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    existing_stmt = select(UserModel).where(UserModel.email == user_data.email)
    existing_result = await db.execute(existing_stmt)
    existing_user = existing_result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        group = group_result.scalars().first()

        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, group.id)
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(id=cast(int, user.id), email=cast(str, user.email))


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate a user account",
    description=(
            "<h3>This endpoint activates a user account using the activation token "
            "that was created during registration.</h3>"
    ),
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "Invalid or expired activation token.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or expired activation token."}
                }
            },
        },
    },
)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = select(UserModel).where(UserModel.email == activation_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_stmt = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    token_result = await db.execute(token_stmt)
    activation_token = token_result.scalars().first()

    if not activation_token or activation_token.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, activation_token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request a password reset token",
    description=(
            "<h3>This endpoint allows a user to request a password reset token. "
            "The response is always the same to avoid leaking whether the email exists.</h3>"
    ),
    responses={
        200: {
            "description": "Password reset instructions will be sent if the user is registered.",
        },
    },
)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete a password reset",
    description=(
            "<h3>This endpoint resets a user password using a valid password reset token.</h3>"
    ),
    responses={
        200: {
            "description": "Password reset successfully.",
        },
        400: {
            "description": "Invalid email or token.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or token."}
                }
            },
        },
        500: {
            "description": "An error occurred while resetting the password.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while resetting the password."}
                }
            },
        },
    },
)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_stmt = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    token_result = await db.execute(token_stmt)
    token_record = token_result.scalars().first()

    if not token_record or token_record.token != reset_data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = reset_data.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="Log in a user",
    description=(
            "<h3>This endpoint authenticates a user and returns access and refresh tokens.</h3>"
    ),
    responses={
        201: {
            "description": "User logged in successfully.",
        },
        401: {
            "description": "Invalid email or password.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or password."}
                }
            },
        },
        403: {
            "description": "User account is not activated.",
            "content": {
                "application/json": {
                    "example": {"detail": "User account is not activated."}
                }
            },
        },
        500: {
            "description": "An error occurred while processing the request.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while processing the request."}
                }
            },
        },
    },
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=cast(int, user.id),
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )

    try:
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh an access token",
    description=(
            "<h3>This endpoint issues a new access token using a valid refresh token.</h3>"
    ),
    responses={
        200: {
            "description": "Access token refreshed successfully.",
        },
        400: {
            "description": "The provided refresh token is invalid or expired.",
            "content": {
                "application/json": {
                    "example": {"detail": "Token has expired."}
                }
            },
        },
        401: {
            "description": "Refresh token not found.",
            "content": {
                "application/json": {
                    "example": {"detail": "Refresh token not found."}
                }
            },
        },
        404: {
            "description": "User not found.",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found."}
                }
            },
        },
    },
)
async def refresh_access_token(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    token_stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_data.refresh_token
    )
    token_result = await db.execute(token_stmt)
    stored_token = token_result.scalars().first()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_stmt = select(UserModel).where(UserModel.id == payload.get("user_id"))
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
