from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings
from config.settings import BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    RegisterRequestSchema,
    RegisterResponseSchema,
    ActivateAccountSchema,
    ActivateAccountResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetRequestResponseSchema,
    PasswordResetCompleteSchema,
    PasswordResetCompleteResponseSchema,
    LoginSchema,
    LoginResponseSchema,
    RefreshTokenSchema,
    RefreshTokenResponseSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=RegisterResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description=(
        "<h3>This endpoint allows users to register a new account.</h3>"
        "<p>The user will be created with an inactive status and an activation token will be generated.</p>"
    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "User with this email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email test@example.com already exists."}
                }
            },
        },
        500: {
            "description": "Internal server error.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        }
    }
)
async def register_user(
    user_data: RegisterRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> RegisterResponseSchema:
    """
    Register a new user.

    This endpoint creates a new user account with the provided email and password.
    The user will be inactive until activated via the activation token.

    :param user_data: The registration data containing email and password.
    :type user_data: RegisterRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: The created user's ID and email.
    :rtype: RegisterResponseSchema

    :raises HTTPException:
        - 409 if a user with this email already exists.
        - 500 if a database error occurs.
    """
    existing_stmt = select(UserModel).where(UserModel.email == user_data.email.lower())
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
        user_group = group_result.scalars().first()

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        user = UserModel.create(
            email=user_data.email.lower(),
            raw_password=user_data.password,
            group_id=user_group.id
        )
        user.is_active = False
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)

        return RegisterResponseSchema.model_validate(user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=ActivateAccountResponseSchema,
    summary="Activate a user account",
    description=(
        "<h3>This endpoint activates a user account using the activation token.</h3>"
        "<p>The user must provide their email and the activation token sent during registration.</p>"
    ),
    responses={
        200: {
            "description": "Account activated successfully.",
        },
        400: {
            "description": "Invalid or expired token, or account already active.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or expired activation token."}
                }
            },
        }
    }
)
async def activate_account(
    activation_data: ActivateAccountSchema,
    db: AsyncSession = Depends(get_db)
) -> ActivateAccountResponseSchema:
    """
    Activate a user account.

    This endpoint activates a user account using the provided email and activation token.
    The token must be valid and not expired.

    :param activation_data: The activation data containing email and token.
    :type activation_data: ActivateAccountSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: A success message.
    :rtype: ActivateAccountResponseSchema

    :raises HTTPException:
        - 400 if the token is invalid, expired, or the account is already active.
    """
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email.lower())
    )
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

    if not user.activation_token or user.activation_token.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = user.activation_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()

    return ActivateAccountResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=PasswordResetRequestResponseSchema,
    summary="Request a password reset token",
    description=(
        "<h3>This endpoint requests a password reset token for a user.</h3>"
        "<p>If the user exists and is active, a password reset token will be created.</p>"
        "<p>For security reasons, this endpoint always returns a success message, even if the user doesn't exist.</p>"
    ),
    responses={
        200: {
            "description": "Password reset token requested successfully.",
        }
    }
)
async def request_password_reset(
    request_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> PasswordResetRequestResponseSchema:
    """
    Request a password reset token.

    This endpoint creates a password reset token for an active user.
    For security, it returns a generic success message even if the user doesn't exist.

    :param request_data: The request data containing the user's email.
    :type request_data: PasswordResetRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: A generic success message.
    :rtype: PasswordResetRequestResponseSchema
    """
    stmt = select(UserModel).where(UserModel.email == request_data.email.lower())
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        existing_token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        existing_token_result = await db.execute(existing_token_stmt)
        existing_token = existing_token_result.scalars().first()

        if existing_token:
            await db.delete(existing_token)

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()

    return PasswordResetRequestResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteResponseSchema,
    summary="Reset password with token",
    description=(
        "<h3>This endpoint resets a user's password using the password reset token.</h3>"
        "<p>The user must provide their email, the reset token, and the new password.</p>"
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
            "description": "Internal server error.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while resetting the password."}
                }
            },
        }
    }
)
async def reset_password(
    reset_data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db)
) -> PasswordResetCompleteResponseSchema:
    """
    Reset a user's password.

    This endpoint resets a user's password using the provided email, token, and new password.
    The token must be valid and not expired.

    :param reset_data: The reset data containing email, token, and new password.
    :type reset_data: PasswordResetCompleteSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: A success message.
    :rtype: PasswordResetCompleteResponseSchema

    :raises HTTPException:
        - 400 if the email or token is invalid.
        - 500 if a database error occurs.
    """
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_data.email.lower())
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if not user.password_reset_token or user.password_reset_token.token != reset_data.token:
        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = user.password_reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(user.password_reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = reset_data.password
        await db.delete(user.password_reset_token)
        await db.commit()

        return PasswordResetCompleteResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=LoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Login a user",
    description=(
        "<h3>This endpoint authenticates a user and returns access and refresh tokens.</h3>"
        "<p>The user must provide valid email and password credentials.</p>"
    ),
    responses={
        201: {
            "description": "Login successful.",
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
            "description": "Internal server error.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while processing the request."}
                }
            },
        }
    }
)
async def login_user(
    login_data: LoginSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> LoginResponseSchema:
    """
    Login a user.

    This endpoint authenticates a user with email and password, and returns
    access and refresh tokens if successful.

    :param login_data: The login data containing email and password.
    :type login_data: LoginSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession
    :param jwt_manager: The JWT authentication manager.
    :type jwt_manager: JWTAuthManagerInterface

    :return: The access and refresh tokens.
    :rtype: LoginResponseSchema

    :raises HTTPException:
        - 401 if the email or password is invalid.
        - 403 if the user account is not activated.
        - 500 if a database error occurs.
    """
    stmt = select(UserModel).where(UserModel.email == login_data.email.lower())
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

    try:
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

        settings: BaseAppSettings = get_settings()
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return LoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=RefreshTokenResponseSchema,
    summary="Refresh access token",
    description=(
        "<h3>This endpoint refreshes an access token using a valid refresh token.</h3>"
        "<p>The user must provide a valid refresh token that exists in the database.</p>"
    ),
    responses={
        200: {
            "description": "Access token refreshed successfully.",
        },
        400: {
            "description": "Token has expired.",
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
        }
    }
)
async def refresh_access_token(
    refresh_data: RefreshTokenSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> RefreshTokenResponseSchema:
    """
    Refresh an access token.

    This endpoint generates a new access token using a valid refresh token.
    The refresh token must exist in the database and be valid.

    :param refresh_data: The refresh data containing the refresh token.
    :type refresh_data: RefreshTokenSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession
    :param jwt_manager: The JWT authentication manager.
    :type jwt_manager: JWTAuthManagerInterface

    :return: A new access token.
    :rtype: RefreshTokenResponseSchema

    :raises HTTPException:
        - 400 if the refresh token has expired.
        - 401 if the refresh token is not found in the database.
        - 404 if the user associated with the token doesn't exist.
    """
    try:
        jwt_manager.verify_refresh_token_or_raise(refresh_data.refresh_token)
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

    token_data = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    user_id = token_data.get("user_id")

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_data.refresh_token
    )
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()

    if not refresh_token_record:
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

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return RefreshTokenResponseSchema(access_token=new_access_token)
