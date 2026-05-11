from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
            "<h3>This endpoint allows a new user to register a new account. "
            "The user provides an email and password that is securely hashed. "
            "An activation token will be automatically generated.</h3>"

    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "User already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with that email already exists."}
                }
            },
        },
        500: {
            "description": "Internal server error.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred during user creation.",
                    }
                }
            }
        }
    },
    status_code=201
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    """
    Register a new user account.
    """
    existing_user_stmt = select(UserModel).where(
        UserModel.email == user_data.email,
    )
    existing_user_result = await db.execute(existing_user_stmt)
    existing_user = existing_user_result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=(
                f"A user with this email {user_data.email} already exists."
            )
        )

    try:
        user_group_stmt = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        user_group_result = await db.execute(user_group_stmt)
        user_group = user_group_result.scalars().first()

        user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)

        return UserRegistrationResponseSchema.model_validate(user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate user account",
    description=(
            "<h3>This endpoint activates a user account "
            "using an activation token.</h3>"

    ),
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "Invalid token or already active account.",
            "content": {
                "application/json": {
                    "example": {
                        "invalid_token" : {
                            "summary": "Invalid token",
                            "value": {
                                "detail": "Invalid or expired activation token."
                            }
                        },
                        "already_active" : {
                            "summary": "Already active",
                            "value": {
                                "detail": "User account is already active."
                            }
                        },
                    }
                }
            },
        },
    },
)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Activate a user account using an activation token.
    """
    user_stmt = select(UserModel).where(
        UserModel.email == activation_data.email,
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    token_stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token,
    )
    token_result = await db.execute(token_stmt)
    activation_token = token_result.scalars().first()

    if not activation_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True

        await db.delete(activation_token)
        await db.commit()

        return MessageResponseSchema(
            message="User account activated successfully."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while activating user account."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request password reset",
    description=(
            "<h3>This endpoint creates a password reset token "
            "for a user account.</h3>"

    ),
    responses={
        200: {
            "description": "Password reset request sent successfully.",
        },
    },
    status_code=200
)
async def request_password_reset(
        request_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Request a password reset token for a user account.
    """
    user_stmt = select(UserModel).where(
        UserModel.email == request_data.email,
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    if not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    token_stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    token_result = await db.execute(token_stmt)
    existing_token = token_result.scalars().first()

    try:
        if existing_token:
            await db.delete(existing_token)
            await db.flush()

        reset_token = PasswordResetTokenModel(
            user_id=user.id,
        )

        db.add(reset_token)

        await db.commit()

        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing password reset request."
        )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
    description=(
            "<h3>This endpoint completes password reset "
            "using a valid request token.</h3>"

    ),
    responses={
        200: {
            "description": "Password reset successfully.",
        },
        400: {
            "description": "Invalid email or token."
        }
    },
    status_code=200
)
async def complete_password_reset(
        request_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Complete password reset using reset token.
    """
    user_stmt = select(UserModel).where(
        UserModel.email == request_data.email,
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    token_stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == request_data.token,
    )
    token_result = await db.execute(token_stmt)
    reset_token = token_result.scalars().first()

    if not reset_token:
        existing_token_stmt = (
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )

        existing_token_result = await db.execute(existing_token_stmt)
        existing_token = existing_token_result.scalars().first()

        if existing_token:
            await db.delete(existing_token)
            await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, reset_token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        user.password = request_data.password

        await db.delete(reset_token)
        await db.commit()

        return MessageResponseSchema(
            message="Password reset successfully."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="Login user",
    description=(
            "<h3>This endpoint authenticates user "
            "and returns access and refresh tokens.</h3>"

    ),
    responses={
        201: {
            "description": "User logged in successfully.",
        },
        401: {
            "description": "Invalid credentials.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or password."
                    }
                }
            }
        },
        403: {
            "description": "User account is not activated.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User account is not activated."
                    }
                }
            }
        }
    },
    status_code=201
)
async def login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    """
    Authenticate user and return JWT tokens.
    """
    user_stmt = (
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.email == login_data.email)
    )
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token(
            data={
                "user_id": user.id,
                "email": user.email,
                "group": user.group.name.value,
            }
        )

        refresh_token = jwt_manager.create_refresh_token(
            data={
                "user_id": user.id,
            }
        )

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )

        db.add(refresh_token_record)

        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh access token",
    description=(
            "<h3>This endpoint generates a new access token "
            "using a valid refresh token.</h3>"

    ),
    responses={
        200: {
            "description": "Access token refreshed successfully.",
        },
        400: {
            "description": "Token has expired.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Token has expired."
                    }
                }
            }
        },
        401: {
            "description": "Refresh token not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Refresh token not found."
                    }
                }
            }
        },
        404: {
            "description": "User not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User not found."
                    }
                }
            }
        }
    },
    status_code=200
)
async def refresh_token(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    """
    Refresh access token using refresh token.
    """
    try:
        payload = jwt_manager.decode_refresh_token(
            request_data.refresh_token
        )

    except BaseSecurityError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    token_stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == request_data.refresh_token
    )

    token_result = await db.execute(token_stmt)
    refresh_token = token_result.scalars().first()

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user_id = int(payload["user_id"])

    user_stmt = (
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == user_id)
    )

    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
            "group": user.group.name.value,
        }
    )

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
