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
    UserActivationResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    RefreshTokenRequestSchema,
    RefreshTokenResponseSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
        "<h3>This endpoint allows new users to register by providing their email and password. "
        "The user will be assigned to the default user group and an activation token will be created "
        "for account verification.</h3>"
        "<p>The password will be securely hashed before storage, and the email will be validated "
        "for proper format and uniqueness.</p>"
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
            "description": "Internal server error during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        }
    },
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    """
    Register a new user and create activation token.

    :param user_data: Registration data with email and password
    :param db: Database session
    :return: User's basic information
    :raises HTTPException: 409 if email exists, 500 for other errors
    """
    try:
        user_stmt = select(UserModel).where(UserModel.email == user_data.email.lower())
        user_result = await db.execute(user_stmt)
        existing_user = user_result.scalars().first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation."
            )

        new_user = UserModel.create(
            email=user_data.email.lower(),
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()

        await db.refresh(new_user)

        return UserRegistrationResponseSchema.model_validate(new_user)

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=UserActivationResponseSchema,
    summary="Activate user account",
    description=(
        "<h3>This endpoint allows users to activate their accounts by providing a valid "
        "activation token and their email address.</h3>"
        "<p>Once activated, the user account becomes fully functional and the activation "
        "token is removed from the system. The user must provide both their email and "
        "the activation token they received during registration.</p>"
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
                            "summary": "Invalid or expired token",
                            "value": {"detail": "Invalid or expired activation token."}
                        },
                        "already_active": {
                            "summary": "Account already active",
                            "value": {"detail": "User account is already active."}
                        }
                    }
                }
            },
        }
    },
    status_code=status.HTTP_200_OK
)
async def activate_user_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserActivationResponseSchema:
    """
    Activate user account using activation token.

    :param activation_data: Email and activation token
    :param db: Database session
    :return: Success message
    :raises HTTPException: 400 if token invalid/expired or account already active
    """
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == activation_data.email.lower()))

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

        token_stmt = (
            select(ActivationTokenModel)
            .options(joinedload(ActivationTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == activation_data.email.lower(),
                ActivationTokenModel.token == activation_data.token
            )
        )
        token_result = await db.execute(token_stmt)
        activation_token = token_result.scalars().first()

        if not activation_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        current_time = datetime.now(timezone.utc)
        token_expires_at = cast(datetime, activation_token.expires_at)

        if token_expires_at.tzinfo is None:
            token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

        if current_time >= token_expires_at:
            await db.delete(activation_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        user.is_active = True

        await db.delete(activation_token)

        await db.commit()

        return UserActivationResponseSchema(
            message="User account activated successfully."
        )

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )


@router.post(
    "/password-reset/request/",
    response_model=PasswordResetResponseSchema,
    summary="Request password reset token",
    description=(
        "<h3>This endpoint allows users to request a password reset token by providing their email address.</h3>"
        "<p>For security reasons, the endpoint always returns the same success message regardless of whether "
        "the user exists or not. This prevents user enumeration attacks while allowing legitimate users "
        "to reset their passwords.</p>"
        "<p>If the user exists and is active, any existing password reset tokens will be invalidated "
        "and a new token will be generated.</p>"
    ),
    responses={
        200: {
            "description": "Password reset request processed successfully.",
            "content": {
                "application/json": {
                    "example": {"message": "If you are registered, you will receive an email with instructions."}
                }
            },
        }
    },
    status_code=status.HTTP_200_OK
)
async def request_password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> PasswordResetResponseSchema:
    """
    Request password reset token. Always returns same message for security.

    :param reset_request: Email address for password reset
    :param db: Database session
    :return: Generic success message
    """
    success_message = "If you are registered, you will receive an email with instructions."

    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == reset_request.email.lower()))

        if user and user.is_active:
            delete_stmt = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            await db.execute(delete_stmt)

            await db.flush()

            new_reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
            db.add(new_reset_token)

            await db.commit()

        return PasswordResetResponseSchema(message=success_message)

    except Exception:
        await db.rollback()
        return PasswordResetResponseSchema(message=success_message)


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteResponseSchema,
    summary="Complete password reset",
    description=(
        "<h3>This endpoint allows users to complete the password reset process by providing "
        "their email, reset token, and new password.</h3>"
        "<p>The system validates the token, ensures it hasn't expired, and updates the user's "
        "password. The reset token is automatically deleted after successful use to prevent "
        "replay attacks.</p>"
        "<p>All validation steps must pass for the password reset to succeed, ensuring "
        "the security and integrity of user accounts.</p>"
    ),
    responses={
        200: {
            "description": "Password reset completed successfully.",
            "content": {
                "application/json": {
                    "example": {"message": "Password reset successfully."}
                }
            },
        },
        400: {
            "description": "Invalid email, token, or the token has expired.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or token."}
                }
            },
        },
        500: {
            "description": "Internal server error during password reset.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while resetting the password."}
                }
            },
        }
    },
    status_code=status.HTTP_200_OK
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> PasswordResetCompleteResponseSchema:
    """
    Complete password reset using valid token.

    :param reset_data: Email, token and new password
    :param db: Database session
    :return: Success message
    :raises HTTPException: 400 if invalid token/email, 500 for errors
    """
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == reset_data.email.lower()))

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        token_stmt = (
            select(PasswordResetTokenModel)
            .options(joinedload(PasswordResetTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == reset_data.email.lower(),
                PasswordResetTokenModel.token == reset_data.token
            )
        )
        token_result = await db.execute(token_stmt)
        reset_token = token_result.scalars().first()

        if not reset_token:
            delete_stmt = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            await db.execute(delete_stmt)

            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        current_time = datetime.now(timezone.utc)
        token_expires_at = cast(datetime, reset_token.expires_at)

        if token_expires_at.tzinfo is None:
            token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

        if current_time >= token_expires_at:
            await db.delete(reset_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = reset_data.password

        await db.delete(reset_token)

        await db.commit()

        return PasswordResetCompleteResponseSchema(
            message="Password reset successfully."
        )

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User login",
    description=(
        "<h3>This endpoint authenticates users with their email and password, "
        "returning access and refresh tokens for API access.</h3>"
        "<p>The access token is used to authenticate API requests, while the refresh token "
        "can be used to obtain new access tokens when they expire. The refresh token is "
        "stored in the database for security tracking and can be revoked if needed.</p>"
        "<p>Users must have activated accounts to successfully log in.</p>"
    ),
    responses={
        201: {
            "description": "User authenticated successfully.",
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
            "description": "Internal server error during login processing.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while processing the request."}
                }
            },
        }
    },
    status_code=status.HTTP_201_CREATED
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    """
    Authenticate user and return access/refresh tokens.

    :param login_data: Email and password
    :param db: Database session
    :param jwt_manager: JWT token manager
    :param settings: App settings
    :return: Access token, refresh token and token type
    :raises HTTPException: 401 invalid credentials, 403 inactive account, 500 errors
    """
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == login_data.email.lower()))

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

        refresh_token = jwt_manager.create_refresh_token({
            "user_id": cast(int, user.id),
            "email": user.email
        })

        access_token = jwt_manager.create_access_token({
            "user_id": cast(int, user.id),
            "email": user.email
        })

        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_record)

        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except HTTPException:
        await db.rollback()
        raise
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
        "<h3>This endpoint allows users to obtain a new access token by providing "
        "a valid refresh token.</h3>"
        "<p>The refresh token must be valid, not expired, and exist in the database. "
        "The associated user must also exist in the system. Upon successful validation, "
        "a new access token is generated and returned.</p>"
        "<p>This mechanism allows users to maintain authenticated sessions without "
        "requiring them to log in again when their access token expires.</p>"
    ),
    responses={
        200: {
            "description": "Access token refreshed successfully.",
        },
        400: {
            "description": "Invalid or expired refresh token.",
            "content": {
                "application/json": {
                    "example": {"detail": "Token has expired."}
                }
            },
        },
        401: {
            "description": "Refresh token not found in database.",
            "content": {
                "application/json": {
                    "example": {"detail": "Refresh token not found."}
                }
            },
        },
        404: {
            "description": "User associated with token not found.",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found."}
                }
            },
        }
    },
    status_code=status.HTTP_200_OK
)
async def refresh_access_token(
    token_data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> RefreshTokenResponseSchema:
    """
    Refresh access token using valid refresh token.

    :param token_data: Refresh token
    :param db: Database session
    :param jwt_manager: JWT token manager
    :return: New access token
    :raises HTTPException: 400 invalid/expired token, 401 token not found, 404 user not found
    """
    try:
        try:
            token_payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        except BaseSecurityError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        user_id = token_payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        refresh_token_stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
        refresh_token_result = await db.execute(refresh_token_stmt)
        refresh_token_record = refresh_token_result.scalars().first()

        if not refresh_token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        if refresh_token_record.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        user = await db.scalar(select(UserModel).where(UserModel.id == user_id))

        if not user:
            await db.delete(refresh_token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token({
            "user_id": cast(int, user.id),
            "email": user.email
        })

        return RefreshTokenResponseSchema(
            access_token=new_access_token
        )

    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
