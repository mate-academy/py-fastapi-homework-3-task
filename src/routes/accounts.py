from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings, get_jwt_auth_manager
from config.settings import BaseAppSettings
from database import get_db
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
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
            "<h3>Register a new user account</h3>"
            "<p>This endpoint allows new users to register by providing their email and password. "
            "Upon successful registration, an activation token is created for the user.</p>"
    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "A user with this email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email user@example.com already exists."}
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
        }
    },
    status_code=201
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    """
    Register a new user.

    This endpoint creates a new user account with the provided email and password.
    The password is hashed before storing. An activation token is generated for
    account activation.

    :param user_data: The registration data containing email and password.
    :type user_data: UserRegistrationRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: The created user's information.
    :rtype: UserRegistrationResponseSchema

    :raises HTTPException:
        - 409 if a user with the same email already exists.
        - 500 if an error occurs during user creation.
    """
    # Check if user already exists
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        # Get default user group
        stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        result_group = await db.execute(stmt_group)
        user_group = result_group.scalars().first()

        if not user_group:
            raise HTTPException(status_code=500, detail="Default user group not found.")

        # Create new user
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )
        db.add(new_user)
        await db.flush()

        # Create activation token
        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema.model_validate(new_user)

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
            "<h3>Activate a user account using an activation token</h3>"
            "<p>This endpoint activates a user account by validating the provided "
            "activation token. Once activated, the token is deleted.</p>"
    ),
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "Invalid or expired activation token, or account already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "value": {"detail": "Invalid or expired activation token."}
                        },
                        "already_active": {
                            "value": {"detail": "User account is already active."}
                        }
                    }
                }
            },
        }
    }
)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Activate a user account.

    This endpoint validates the activation token and activates the user account.
    The activation token is deleted after successful activation.

    :param activation_data: The activation data containing email and token.
    :type activation_data: UserActivationRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: Success message.
    :rtype: MessageResponseSchema

    :raises HTTPException:
        - 400 if the token is invalid, expired, or the account is already active.
    """
    # Get user by email
    stmt = select(UserModel).where(UserModel.email == activation_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    # Check if already active
    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    # Get activation token
    stmt_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token
    )
    result_token = await db.execute(stmt_token)
    token = result_token.scalars().first()

    if not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    # Check if token is expired
    expires_at = cast(datetime, token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    # Activate user and delete token
    user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request password reset token",
    description=(
            "<h3>Request a password reset token</h3>"
            "<p>This endpoint allows users to request a password reset token. "
            "The response is always the same to prevent information leakage about "
            "whether a user exists or not.</p>"
    ),
    responses={
        200: {
            "description": "Request processed successfully.",
        }
    }
)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Request a password reset token.

    This endpoint generates a password reset token for active users.
    The response is always the same to prevent information leakage.

    :param reset_data: The request data containing the user's email.
    :type reset_data: PasswordResetRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: Generic success message.
    :rtype: MessageResponseSchema
    """
    # Get user by email
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    # Only create token if user exists and is active
    if user and user.is_active:
        # Delete any existing password reset tokens
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        # Create new password reset token
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    # Always return the same message to prevent information leakage
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
    description=(
            "<h3>Complete the password reset process</h3>"
            "<p>This endpoint allows users to reset their password using a valid "
            "password reset token.</p>"
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
        }
    }
)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    """
    Complete the password reset process.

    This endpoint validates the password reset token and updates the user's password.
    The token is deleted after successful password reset.

    :param reset_data: The reset data containing email, token, and new password.
    :type reset_data: PasswordResetCompleteRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession

    :return: Success message.
    :rtype: MessageResponseSchema

    :raises HTTPException:
        - 400 if the email or token is invalid or expired.
        - 500 if an error occurs during password reset.
    """
    # Get user by email
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    # Get password reset token
    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result_token = await db.execute(stmt_token)
    token = result_token.scalars().first()

    if not token or token.token != reset_data.token:
        # Delete any existing token if found (even if it doesn't match)
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    # Check if token is expired
    expires_at = cast(datetime, token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        # Delete expired token
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        # Update password using the model's password setter
        # This will automatically validate and hash the password
        user.password = reset_data.password

        # Delete the used token
        await db.delete(token)

        await db.commit()
        await db.refresh(user)

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User login",
    description=(
            "<h3>Authenticate a user and generate tokens</h3>"
            "<p>This endpoint authenticates a user with their email and password, "
            "and returns access and refresh tokens upon successful login.</p>"
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
            "description": "An error occurred while processing the request.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while processing the request."}
                }
            },
        }
    },
    status_code=201
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> UserLoginResponseSchema:
    """
    Authenticate a user and generate tokens.

    This endpoint validates the user's credentials and generates access and refresh tokens.
    The refresh token is stored in the database.

    :param login_data: The login data containing email and password.
    :type login_data: UserLoginRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession
    :param jwt_manager: The JWT authentication manager.
    :type jwt_manager: JWTAuthManagerInterface

    :return: Access and refresh tokens.
    :rtype: UserLoginResponseSchema

    :raises HTTPException:
        - 401 if the email or password is invalid.
        - 403 if the user account is not activated.
        - 500 if an error occurs during the login process.
    """
    # Get user by email
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    # Validate credentials
    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    # Check if account is activated
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        # Generate tokens
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        # Store refresh token in database
        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=7,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
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
            "<h3>Refresh an access token using a refresh token</h3>"
            "<p>This endpoint allows users to obtain a new access token by providing "
            "a valid refresh token.</p>"
    ),
    responses={
        200: {
            "description": "Access token refreshed successfully.",
        },
        400: {
            "description": "Token has expired or is invalid.",
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
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    """
    Refresh an access token.

    This endpoint validates a refresh token and generates a new access token.

    :param token_data: The refresh token data.
    :type token_data: TokenRefreshRequestSchema
    :param db: The async SQLAlchemy database session.
    :type db: AsyncSession
    :param jwt_manager: The JWT authentication manager.
    :type jwt_manager: JWTAuthManagerInterface

    :return: New access token.
    :rtype: TokenRefreshResponseSchema

    :raises HTTPException:
        - 400 if the token has expired or is invalid.
        - 401 if the refresh token is not found in the database.
        - 404 if the user associated with the token does not exist.
    """
    try:
        # Decode and validate refresh token
        token_payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = token_payload.get("user_id")

    except Exception as e:
        error_message = str(e)
        if "expired" in error_message.lower():
            raise HTTPException(
                status_code=400,
                detail="Token has expired."
            )
        raise HTTPException(
            status_code=400,
            detail="Invalid token."
        )

    # Check if refresh token exists in database
    stmt_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == token_data.refresh_token
    )
    result_token = await db.execute(stmt_token)
    refresh_token_record = result_token.scalars().first()

    if not refresh_token_record:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    # Check if user exists
    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    # Generate new access token
    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=access_token)
