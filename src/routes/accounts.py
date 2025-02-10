from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

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

from security.passwords import hash_password, verify_password


from schemas.accounts import (
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

from exceptions.security import TokenExpiredError

from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
        "<h3>This endpoint allows new users to register "
        "by providing their email and password.</h3>"
    ),
    responses={
        201: {
            "description": "User registered successfully.",
        },
        409: {
            "description": "A user with the same email already exists.",
        },
        500: {
            "description": "An error occurred during user creation.",
        }
    },
    status_code=201
)
def user_creation(
    user_data: UserRegistrationRequestSchema,
    db: Session = Depends(get_db)
) -> UserRegistrationResponseSchema:
    """
    Register (add) a new user to the database.

    This endpoint allows new users to register by providing their email and password.

    :param user_data: The data required to create a new user.
    :type user_data: UserRegistrationRequestSchema
    :param db: The SQLAlchemy database session (provided via dependency injection).
    :type db: Session

    :return: The created user.
    :rtype: UserRegistrationResponseSchema
    """
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    hashed_pass = hash_password(user_data.password)

    user_group = db.query(UserGroupModel).filter(UserGroupModel.name == "USER").first()
    if not user_group:
        user_group = UserGroupModel(name="USER")
        db.add(user_group)
        db.commit()

    try:
        user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_pass,
            group=user_group,

        )

        activation_token = ActivationTokenModel(user=user)
        db.add(activation_token)

        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    description=(
        "<h3>This endpoint allows users to activate their accounts by "
        "providing a valid activation token and email. </h3>"
    ),
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "An error occurred during user activation.",
        },
    },
    status_code=200
)
def user_activation(
    activation_data: UserActivationRequestSchema,
    db: Session = Depends(get_db)
) -> MessageResponseSchema:
    """
    Activation user accounts by providing a valid activation token and email.

    :param activation_data: user's email & activation_token
    :type activation_data: UserActivationRequestSchema
    :param db: The SQLAlchemy database session (provided via dependency injection).
    :type db: Session

    :return: Message indicating that the user was successfully activated,
        or that the token has expired/is invalid,
        or that the user has already been activated before.
    :rtype: MessageResponseSchema.
    """
    token = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == activation_data.token).first()
    user = db.query(UserModel).filter(UserModel.email == activation_data.email).first()

    if token is None or token.user_id != user.id:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    try:
        if not user.is_active:
            user.is_active = True
        else:
            raise HTTPException(status_code=400, detail="User account is already active.")

        db.flush()
        db.delete(token)
        db.commit()
        return MessageResponseSchema(message="User account activated successfully.")

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=400)


@router.post(
    "/password-reset/request/",
    description=(
        "<h3>This endpoint allows users to request a password reset token. </h3>"
    ),
    responses={
        200: {
            "description": "If user is registered, will receive an email with instructions.",
        },
        400: {
            "description": "An error occurred during password reset request.",
        }
    },
    status_code=200
)
def user_password_reset(
    user_data: PasswordResetRequestSchema,
    db: Session = Depends(get_db)
):
    """
    This endpoint allows users to request a password reset token. The endpoint ensures
    that no sensitive user information is leaked while providing a mechanism
    to reset passwords securely.

    :param user_data: user's email
    :type user_data: PasswordResetRequestSchema
    :param db: The SQLAlchemy database session (provided via dependency injection).
    :type db: Session

    :return: The endpoint always responds with message: an email with instructions.
    :rtype: dict
    """
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if user:
        try:
            if user and user.is_active:
                tokens = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id)
                if tokens:
                    for token in tokens:
                        db.delete(token)

                pass_reset_token = PasswordResetTokenModel(user=user)
                db.add(pass_reset_token)
                db.flush()
                db.commit()
                db.refresh(pass_reset_token)

        except SQLAlchemyError:
            db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    description=(
        "<h3>This endpoint allows users to reset their password "
        "using a valid password reset token.</h3>"
    ),
    responses={
        200: {
            "description": "Password reset successfully.",
        },
        400: {
            "description": "Invalid email or token.",
        },
        500: {
            "description": "An error occurred while resetting the password.",
        }
    },
    status_code=200
)
def user_password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db)
) -> MessageResponseSchema:

    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id
    ).first()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if (token.token != user_data.token
            or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)):
        db.delete(token)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    hashed_pass = hash_password(user_data.password)
    try:
        user._hashed_password = hashed_pass
        db.delete(token)
        db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    description=(
        "<h3>This endpoint authenticates a user based on their email and password, "
        "generates access and refresh tokens upon successful login, "
        "and stores the refresh token in the database. </h3>"
    ),
    responses={
        401: {
            "description": "Invalid email or password.",
        },
        403: {
            "description": "User account is not activated.",
        },
        500: {
            "description": "An error occurred while processing the request.",
        }
    },
    status_code=201
)
def user_login(
    user_data: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
) -> UserLoginResponseSchema:
    """
    This endpoint authenticates a user based on their email and password,
    generates access and refresh tokens upon successful login,
    and stores the refresh token in the database.

    :param user_data: user's email and password
    :type user_data: UserLoginRequestSchema
    :param db: The SQLAlchemy database session (provided via dependency injection).
    :type db: Session

    :return: The endpoint response with access_token, refresh_token and token_type.
    :rtype: UserLoginResponseSche
    """
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not verify_password(user_data.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

        db_refresh_token = RefreshTokenModel(user=user, token=refresh_token)
        db.add(db_refresh_token)
        user.refresh_tokens.append(db_refresh_token)

        db.add(user)
        db.commit()
        db.refresh(user)

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    description=(
        "<h3>This endpoint allows users to refresh their access token by providing "
        "a valid refresh token. </h3>"
    ),
    responses={
        200: {
            "description": "Access token successfully refreshed.",
        },
        400: {
            "description": "Token has expired.",
        },
        401: {
            "description": "Refresh token not found.",
        },
        404: {
            "description": "User not found.",
        }
    },
    status_code=200
)
def token_refresh(
    token_data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    """
    This endpoint allows users to refresh their access token by providing a valid refresh token.

    :param token_data: valid user's refresh_token
    :type token_data: TokenRefreshRequestSchema
    :param db: The SQLAlchemy database session (provided via dependency injection).
    :type db: Session

    :return: The endpoint response with new access_token, or raise that refresh_token has expired.
    :rtype: TokenRefreshResponseSchema
    """
    try:
        token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        if not token:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == token_data.refresh_token).first()
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = token.get("user_id")
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
