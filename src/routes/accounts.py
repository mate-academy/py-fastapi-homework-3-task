from datetime import datetime, timezone, timedelta
from typing import cast
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from config.dependencies import get_jwt_auth_manager, get_settings
from config.settings import BaseAppSettings
from database.session_postgresql import get_db
from database.models.base import UserGroupEnum
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from exceptions.security import InvalidTokenError

router = APIRouter(prefix="/accounts", tags=["Accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    """
    Task 1: Implement User Registration Endpoint.
    Registers a new user, creates an activation token, and returns user info.
    """
    # Check if user already exists
    existing_user_result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    # Get the default "USER" group
    group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = group_result.scalar_one_or_none()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found. Please contact support.",
        )

    try:
        # Create new user
        hashed_pwd = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            hashed_password=hashed_pwd,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()  # Flush to get the new_user.id

        # Create activation token
        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    """
    Task 2: Implement User Account Activation Endpoint.
    Activates a user's account using a valid token.
    """
    # Find the token
    token_result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token
        )
    )
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    # Check token expiry (using hint for SQLite compatibility)
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    # Find the user
    user_result = await db.execute(
        select(UserModel).where(UserModel.id == token_record.user_id)
    )
    user = user_result.scalar_one_or_none()

    if not user or user.email != activation_data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    # Activate user and delete token
    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
    request_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    """
    Task 3: Implement Password Reset Token Request Endpoint.
    Generates a password reset token if the user exists and is active.
    Always returns a generic success message to prevent user enumeration.
    """
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    user = user_result.scalar_one_or_none()

    if user and user.is_active:
        try:
            # Delete any existing reset tokens for this user
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )

            # Create a new reset token
            reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
            db.add(reset_token)
            await db.commit()
        except Exception:
            await db.rollback()
            # Log the error internally, but don't expose it to the client
            pass

    # Always return a success response
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
):
    """
    Task 4: Implement Password Reset Completion Endpoint.
    Resets the user's password using a valid token.
    """
    # Find the token
    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == reset_data.token
        )
    )
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    # Check token expiry
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    # Find the user
    user_result = await db.execute(
        select(UserModel).where(UserModel.id == token_record.user_id)
    )
    user = user_result.scalar_one_or_none()

    if not user or user.email != reset_data.email or not user.is_active:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        # Update password
        user.hashed_password = hash_password(reset_data.password)
        
        # Delete the token
        await db.delete(token_record)
        
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    """
    Task 5: Implement User Login Endpoint.
    Authenticates a user and returns access and refresh tokens.
    """
    # Find user
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == login_data.email)
    )
    user = user_result.scalar_one_or_none()

    # Validate user and password
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        # Generate tokens
        user_id = cast(int, user.id)
        access_token = jwt_manager.create_access_token(user_id=user_id)
        
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token_str = jwt_manager.create_refresh_token(
            user_id=user_id, expires_delta=expires_delta
        )
        expires_at = datetime.now(timezone.utc) + expires_delta

        # Store the refresh token in the database
        db_refresh_token = RefreshTokenModel(
            user_id=user_id,
            token=refresh_token_str,
            expires_at=expires_at
        )
        db.add(db_refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh_access_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    """
    Task 6: Implement Access Token Refresh Endpoint.
    Generates a new access token from a valid refresh token.
    """
    try:
        # Decode the refresh token (checks signature and expiry)
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = payload.get("user_id")
        if user_id is None:
            raise InvalidTokenError("Invalid token payload.")
            
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Check if the token exists in the database
    token_result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_data.refresh_token,
            RefreshTokenModel.user_id == user_id
        )
    )
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    # Check if the user associated with the token still exists
    user_result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # Generate a new access token
    new_access_token = jwt_manager.create_access_token(user_id=cast(int, user.id))
    return TokenRefreshResponseSchema(access_token=new_access_token)
