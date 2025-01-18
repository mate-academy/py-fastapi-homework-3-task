from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError, InvalidTokenError, TokenExpiredError
from schemas import (
    LoginRequestSchema,
    LoginResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    RefreshTokenRequestSchema,
    RefreshTokenResponseSchema,
    UserActivationRequestSchema,
    UserActivationResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
        "<h3>This endpoint allows new users to register in the system. "
        "It creates a new user account with the provided email and password, "
        "assigns them to the default user group, and generates an activation token. "
        "The user must activate their account using this token before they can log in.</h3>"
    ),
    responses={
        status.HTTP_201_CREATED: {"description": "User registered successfully."},
        status.HTTP_409_CONFLICT: {
            "description": "A user with the same email already exists.",
            "content": {
                "application/json": {"example": {"detail": "A user with this email test@example.com already exists."}}
            },
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error.",
            "content": {"application/json": {"example": {"detail": "An error occurred during user creation."}}},
        },
    },
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)
) -> UserRegistrationResponseSchema:
    """
    Register a new user in the system.

    This endpoint creates a new user account with the provided email and password.
    It also generates an activation token that will be needed to activate the account.
    The user is assigned to the default user group (USER).

    Attributes:
        user_data (UserRegistrationRequestSchema): The registration data containing email and password.
        db (Session): The database session (provided via dependency injection).

    Returns:
        UserRegistrationResponseSchema: The created user's ID and email.

    Raises:
        HTTPException:
            - 409: If a user with the provided email already exists.
            - 500: If an error occurs during user creation.
    """
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        user_group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found.",
            )

        user = UserModel.create(
            email=cast(str, user_data.email), raw_password=user_data.password, group_id=user_group.id
        )
        db.add(user)
        db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        db.commit()
        db.refresh(user)

        return UserRegistrationResponseSchema.model_validate(user)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=UserActivationResponseSchema,
    summary="Activate user account",
    description=(
        "<h3>This endpoint activates a user account using the provided activation token. "
        "The token must be valid and not expired. After successful activation, "
        "the user will be able to log in to their account.</h3>"
    ),
    responses={
        status.HTTP_200_OK: {
            "description": "User account activated successfully.",
            "content": {"application/json": {"example": {"message": "User account activated successfully."}}},
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Invalid token or user already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {"value": {"detail": "Invalid or expired activation token."}},
                        "already_active": {"value": {"detail": "User account is already active."}},
                    }
                }
            },
        },
    },
)
def activate_user(
    activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)
) -> UserActivationResponseSchema:
    """
    Activate a user account using the provided activation token.

    This endpoint validates the activation token and activates the user's account
    if the token is valid and not expired. After successful activation, the token
    is deleted from the database.

    Attributes:
        activation_data (UserActivationRequestSchema): The activation data containing email and token.
        db (Session): The database session (provided via dependency injection).

    Returns:
        UserActivationResponseSchema: A success message indicating the account was activated.

    Raises:
        HTTPException:
            - 400: If the token is invalid/expired or the user is already active.
    """
    user = db.query(UserModel).filter(UserModel.email == activation_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email does not exist.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    activation_token = (
        db.query(ActivationTokenModel)
        .filter(ActivationTokenModel.user_id == user.id, ActivationTokenModel.token == activation_data.token)
        .first()
    )
    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    token_expires_at = activation_token.expires_at.replace(tzinfo=timezone.utc)
    if token_expires_at < datetime.now(timezone.utc):
        db.delete(activation_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        db.delete(activation_token)
        db.commit()
        return UserActivationResponseSchema(message="User account activated successfully.")
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the account.",
        )


@router.post(
    "/password-reset/request/",
    response_model=PasswordResetResponseSchema,
    summary="Request password reset token",
    description=(
        "<h3>This endpoint allows users to request a password reset token. "
        "If the provided email exists and belongs to an active user, "
        "a password reset token will be generated. For security reasons, "
        "the same success message it returned regardless of whether the email exists.</h3>"
    ),
    responses={
        status.HTTP_200_OK: {
            "description": "Password reset token request processed.",
            "content": {
                "application/json": {
                    "example": {"message": "If you are registered, you will receive an email with instructions."}
                }
            },
        }
    },
)
def request_password_reset(
    reset_data: PasswordResetRequestSchema, db: Session = Depends(get_db)
) -> PasswordResetResponseSchema:
    """
    Request a password reset token.

    This endpoint handles password reset token requests. If the email exists
    and belongs to an active user, it generates a new reset token. For security,
    it always returns the same success message to prevent email enumeration.

    Attributes:
        reset_data (PasswordResetRequestSchema): The password reset request data containing the email.
        db (Session): The database session (provided via dependency injection).

    Returns:
        PasswordResetResponseSchema: A message indicating that instructions will be sent if the email is registered.
    """
    user = db.query(UserModel).filter(UserModel.email == reset_data.email).first()

    if user and user.is_active:
        try:
            existing_token = (
                db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()
            )
            if existing_token:
                db.delete(existing_token)

            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            pass

    return PasswordResetResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteResponseSchema,
    summary="Complete password reset",
    description=(
        "<h3>This endpoint completes the password reset process by validating the reset token "
        "and updating the user's password. The token must be valid and not expired. "
        "After successful password reset, the token is invalidated.</h3>"
    ),
    responses={
        status.HTTP_200_OK: {
            "description": "Password reset successfully.",
            "content": {"application/json": {"example": {"message": "Password reset successfully."}}},
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Invalid email or token.",
            "content": {"application/json": {"example": {"detail": "Invalid email or token."}}},
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error.",
            "content": {
                "application/json": {"example": {"detail": "An error occurred while resetting the password."}}
            },
        },
    },
)
def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)
) -> PasswordResetCompleteResponseSchema:
    """
    Complete the password reset process.

    This endpoint validates the reset token and updates the user's password.
    The token must be valid and not expired. After successful password reset,
    the token is invalidated to prevent reuse.

    Attributes:
        reset_data (PasswordResetCompleteRequestSchema): The password reset completion data containing
        email, token, and new password.
        db (Session): The database session (provided via dependency injection).

    Returns:
        PasswordResetCompleteResponseSchema: A success message indicating the password was reset.

    Raises:
        HTTPException:
            - 400: If the email or token is invalid.
            - 500: If an error occurs while resetting the password.
    """
    user = db.query(UserModel).filter(UserModel.email == reset_data.email).first()
    if not user:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == reset_data.token).delete()
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    reset_token = (
        db.query(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.user_id == user.id, PasswordResetTokenModel.token == reset_data.token)
        .first()
    )
    if not reset_token:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    token_expires_at = reset_token.expires_at.replace(tzinfo=timezone.utc)
    if token_expires_at < datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user.password = reset_data.password
        db.delete(reset_token)
        db.commit()

        return PasswordResetCompleteResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=LoginResponseSchema,
    summary="Login user",
    description=(
        "<h3>This endpoint authenticates a user using their email and password. "
        "If the credentials are valid and the account is activated, "
        "it returns access and refresh tokens for subsequent API calls.</h3>"
    ),
    responses={
        status.HTTP_201_CREATED: {
            "description": "Successfully authenticated.",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer",
                    }
                }
            },
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Invalid credentials.",
            "content": {"application/json": {"example": {"detail": "Invalid email or password."}}},
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Account not activated.",
            "content": {"application/json": {"example": {"detail": "User account is not activated."}}},
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal server error.",
            "content": {
                "application/json": {"example": {"detail": "An error occurred while processing the request."}}
            },
        },
    },
    status_code=status.HTTP_201_CREATED,
)
def login_user(
    login_data: LoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> LoginResponseSchema:
    """
    Authenticate a user and generate access and refresh tokens.

    This endpoint validates the user's credentials and, if successful,
    generates an access token for API access and a refresh token for
    obtaining new access tokens.

    Attributes:
        login_data (LoginRequestSchema): The login credentials (email and password).
        db (Session): The database session (provided via dependency injection).
        jwt_manager (JWTAuthManagerInterface): The JWT manager for token operations.
        settings (BaseAppSettings): Application settings.

    Returns:
        LoginResponseSchema: Access and refresh tokens.

    Raises:
        HTTPException:
            - 401: If the credentials are invalid.
            - 403: If the user account is not activated.
            - 500: If an error occurs during token generation.
    """
    user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
    if not user or not user.verify_password(login_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    try:
        token_data = {"user_id": user.id}
        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)

        db_refresh_token = RefreshTokenModel.create(
            user_id=cast(int, user.id), days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(db_refresh_token)
        db.commit()

        return LoginResponseSchema(access_token=access_token, refresh_token=refresh_token, token_type="bearer")
    except (SQLAlchemyError, BaseSecurityError):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=RefreshTokenResponseSchema,
    summary="Refresh access token",
    description=(
        "<h3>This endpoint allows users to obtain a new access token using their refresh token. "
        "The refresh token must be valid and exist in the database. "
        "If successful, a new access token is generated.</h3>"
    ),
    responses={
        status.HTTP_200_OK: {
            "description": "Access token refreshed successfully.",
            "content": {"application/json": {"example": {"access_token": "new_access_token"}}},
        },
        status.HTTP_400_BAD_REQUEST: {
            "description": "Invalid or expired refresh token.",
            "content": {"application/json": {"example": {"detail": "Token has expired."}}},
        },
        status.HTTP_401_UNAUTHORIZED: {
            "description": "Refresh token not found.",
            "content": {"application/json": {"example": {"detail": "Refresh token not found."}}},
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "User not found.",
            "content": {"application/json": {"example": {"detail": "User not found."}}},
        },
    },
)
def refresh_access_token(
    refresh_data: RefreshTokenRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> RefreshTokenResponseSchema:
    """
    Refresh the access token using a valid refresh token.

    This endpoint validates the provided refresh token and generates a new access token
    if the refresh token is valid and exists in the database.

    Attributes:
        refresh_data (RefreshTokenRequestSchema): The refresh token data.
        db (Session): The database session (provided via dependency injection).
        jwt_manager (JWTAuthManagerInterface): The JWT manager for token operations.

    Returns:
        RefreshTokenResponseSchema: A new access token.

    Raises:
        HTTPException:
            - 400: If the refresh token is invalid or expired.
            - 401: If the refresh token is not found in the database.
            - 404: If the user associated with the token is not found.
    """
    try:
        token_data = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = token_data.get("user_id")

        if not user_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token format.")

        refresh_token = (
            db.query(RefreshTokenModel).filter(RefreshTokenModel.token == refresh_data.refresh_token).first()
        )
        if not refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

        user = db.query(UserModel).filter(UserModel.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        new_token_data = {"user_id": user.id}
        new_access_token = jwt_manager.create_access_token(data=new_token_data)

        return RefreshTokenResponseSchema(access_token=new_access_token)

    except TokenExpiredError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    except InvalidTokenError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
