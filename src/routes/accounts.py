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
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description=(
        "<h3>Register a new user by providing an email and password. "
        "An activation token will be created for the user. "
        "Returns the new user's ID and email on success.</h3>"
    ),
    responses={
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
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    """
    Register a new user account.

    Checks for duplicate email, hashes the password, assigns the default USER group,
    creates an activation token, and commits everything to the database.

    :param user_data: Registration payload (email + password).
    :param db: Async database session.
    :return: The newly created user's ID and email.
    :raises HTTPException 409: If the email is already registered.
    :raises HTTPException 500: If an unexpected database error occurs.
    """
    existing_stmt = select(UserModel).where(UserModel.email == user_data.email)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        user_group = group_result.scalars().first()

        new_user = UserModel(
            email=user_data.email,
            group=user_group,
        )
        new_user.password = user_data.password  # hashed via model setter / validator

        activation_token = ActivationTokenModel(user=new_user)
        db.add(new_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema.model_validate(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    summary="Activate a user account",
    description=(
        "<h3>Activate a user account using the activation token sent to the user's email. "
        "The token must be valid and not expired.</h3>"
    ),
    responses={
        400: {
            "description": "Invalid/expired token or account already active.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or expired activation token."}
                }
            },
        },
    },
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Activate a user account with the provided email and activation token.

    :param activation_data: Payload containing email and activation token.
    :param db: Async database session.
    :return: Success message dict.
    :raises HTTPException 400: If the token is invalid/expired or the account is already active.
    """
    stmt = (
        select(ActivationTokenModel)
        .join(UserModel)
        .where(UserModel.email == activation_data.email)
        .where(ActivationTokenModel.token == activation_data.token)
        .options(joinedload(ActivationTokenModel.user))
    )
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    summary="Request a password reset token",
    description=(
        "<h3>Request a password reset token for the given email address. "
        "Always returns the same success message to avoid leaking user existence.</h3>"
    ),
)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Issue a password-reset token for an active user.

    Always returns a generic success message regardless of whether the user exists,
    to prevent email enumeration attacks.

    :param reset_data: Payload containing the user's email.
    :param db: Async database session.
    :return: Generic success message dict.
    """
    generic_response = {"message": "If you are registered, you will receive an email with instructions."}

    user_stmt = select(UserModel).where(UserModel.email == reset_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.is_active:
        return generic_response

    # Delete any existing reset tokens for this user
    delete_stmt = delete(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == cast(int, user.id)
    )
    await db.execute(delete_stmt)

    # Create a fresh reset token
    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return generic_response


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    summary="Complete a password reset",
    description=(
        "<h3>Complete the password reset process by providing the reset token and the new password. "
        "The token must be valid and not expired.</h3>"
    ),
    responses={
        400: {
            "description": "Invalid email, token, or expired token.",
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
async def reset_password_complete(
    reset_data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Complete the password reset using the provided token and set a new password.

    :param reset_data: Payload with email, reset token, and new password.
    :param db: Async database session.
    :return: Success message dict.
    :raises HTTPException 400: If the token is invalid, expired, or the user is inactive.
    :raises HTTPException 500: If a database error occurs while updating the password.
    """
    stmt = (
        select(PasswordResetTokenModel)
        .join(UserModel)
        .where(UserModel.email == reset_data.email)
        .where(PasswordResetTokenModel.token == reset_data.token)
        .options(joinedload(PasswordResetTokenModel.user))
    )
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user = token_record.user
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = reset_data.password  # hashed via model setter / validator
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="User login",
    description=(
        "<h3>Authenticate a user with their email and password. "
        "Returns JWT access and refresh tokens on success.</h3>"
    ),
    responses={
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
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    """
    Authenticate a user and issue JWT tokens.

    :param login_data: Payload containing email and password.
    :param db: Async database session.
    :param jwt_manager: JWT auth manager (injected).
    :param settings: Application settings (injected).
    :return: Access token, refresh token, and token type.
    :raises HTTPException 401: If credentials are invalid.
    :raises HTTPException 403: If the account is not activated.
    :raises HTTPException 500: If a database error occurs during token storage.
    """
    user_stmt = select(UserModel).where(UserModel.email == login_data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})
    refresh_token = jwt_manager.create_refresh_token({"user_id": cast(int, user.id)})

    try:
        new_refresh_token = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(new_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description=(
        "<h3>Exchange a valid refresh token for a new access token.</h3>"
    ),
    responses={
        400: {
            "description": "The refresh token is invalid or expired.",
            "content": {
                "application/json": {
                    "example": {"detail": "Token has expired."}
                }
            },
        },
        401: {
            "description": "Refresh token not found in the database.",
            "content": {
                "application/json": {
                    "example": {"detail": "Refresh token not found."}
                }
            },
        },
        404: {
            "description": "User associated with the token not found.",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found."}
                }
            },
        },
    },
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """
    Validate a refresh token and issue a new access token.

    :param token_data: Payload containing the refresh token.
    :param db: Async database session.
    :param jwt_manager: JWT auth manager (injected).
    :return: New access token.
    :raises HTTPException 400: If the token is invalid or expired.
    :raises HTTPException 401: If the token is not found in the database.
    :raises HTTPException 404: If the user is not found.
    """
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    user_id = payload.get("user_id")

    # Verify the token exists in the database
    token_stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == token_data.refresh_token
    )
    token_result = await db.execute(token_stmt)
    stored_token = token_result.scalars().first()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    # Verify the associated user exists
    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": cast(int, user.id)})

    return TokenRefreshResponseSchema(access_token=new_access_token)