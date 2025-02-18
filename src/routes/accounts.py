from datetime import datetime, timezone
from pyexpat.errors import messages
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)

from crud import (
    get_user_by_email,
    get_user_by_id,
    create_activation_token,
    create_reset_token,
    get_refresh_token,
    create_and_store_refresh_token
)

from database.validators.accounts import validate_password_strength

from exceptions.security import InvalidTokenError, TokenExpiredError

router = APIRouter()


@router.post(
    path="/register", response_model=UserRegistrationResponseSchema, status_code=201
)
def register(
        user: UserRegistrationRequestSchema, db: Session = Depends(get_db)
) -> UserRegistrationResponseSchema:
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        validate_password_strength(user.password)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    return create_activation_token(db, user)


@router.post(
    path="/activate",
    responses={
        200: {
            "description": "User account activated successfully.",
        },
        400: {
            "description": "Invalid or expired activation token.",
            "content": {
                "application/json": {"example": {"detail": "Invalid input data."}}
            },
        },
    },
    status_code=200,
)
def activate_token(
        activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)
) -> MessageResponseSchema:
    """
    Allows users activating their accounts by providing
    a valid activation_data (token and email).
    """
    db_user = get_user_by_email(db, activation_data.email)
    db_token = (
        db.query(ActivationTokenModel)
        .filter(ActivationTokenModel.user_id == db_user.id)
        .first()
    )
    if not db_token and not db_user.is_active:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)
    if (
            expires_at < datetime.now(timezone.utc)
            or db_token.token != activation_data.token
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    db.delete(db_token)
    db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(path="/password-reset/request/", response_model=MessageResponseSchema)
def password_reset_token(
        user_data: PasswordResetRequestSchema, db: Session = Depends(get_db)
) -> MessageResponseSchema:
    db_user = get_user_by_email(db, user_data.email)

    if not db_user:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    db_reset_token = (
        db.query(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.user_id == db_user.id)
        .first()
    )

    if db_reset_token:
        db.delete(db_reset_token)
        db.commit()

    if db_user.is_active:
        create_reset_token(db, db_user)

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(path="/reset-password/complete", response_model=MessageResponseSchema)
def password_reset_completion(
        reset_data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)
) -> MessageResponseSchema:
    db_user = get_user_by_email(db, reset_data.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    db_reset_token = (
        db.query(PasswordResetTokenModel)
        .filter(PasswordResetTokenModel.user_id == db_user.id)
        .first()
    )
    if not db_reset_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, db_reset_token.expires_at).replace(tzinfo=timezone.utc)
    if (
            expires_at < datetime.now(timezone.utc)
            or db_reset_token.token != reset_data.token
    ):
        db.delete(db_reset_token)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = reset_data.password
        db.delete(db_reset_token)
        db.commit()
        db.refresh(db_user)
        return MessageResponseSchema(message="Password reset successfully.")
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )


@router.post(
    path="/login",
    response_model=UserLoginResponseSchema,
    status_code=201
)
def login(
        user_data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    db_user = get_user_by_email(db, user_data.email)
    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )

    try:
        db_refresh_token = get_refresh_token(db_user, db)
        if not db_refresh_token:
            db_refresh_token = create_and_store_refresh_token(
                db_user, db, jwt_manager, settings
            )

        expires_at = cast(datetime, db_refresh_token.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            db.delete(db_refresh_token)
            db.commit()
            # recreate new refresh token because of expired previous token
            db_refresh_token = create_and_store_refresh_token(
                db_user, db, jwt_manager, settings
            )
        try:
            jwt_manager.decode_refresh_token(db_refresh_token.token)
        except InvalidTokenError:
            db.delete(db_refresh_token)
            db.commit()
            db_refresh_token = create_and_store_refresh_token(
                db_user, db, jwt_manager, settings
            )

        access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=db_refresh_token.token,
            token_type="bearer"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )


@router.post(
    path="/refresh",
    response_model=TokenRefreshResponseSchema,
    status_code=200
)
def refresh_access_token(
        refresh_token: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    # token validation - return user's email and exp_date
    str_refresh_token = TokenRefreshRequestSchema.model_validate(refresh_token).refresh_token
    try:
        decoded_data = jwt_manager.decode_refresh_token(
            token=str_refresh_token
        )
        db_refresh_token = (
            db.query(RefreshTokenModel)
            .filter(RefreshTokenModel.token == str_refresh_token)
            .first()
        )
        if not db_refresh_token:
            raise HTTPException(
                status_code=401,
                detail="Refresh token not found."
            )
    except InvalidTokenError:
        raise HTTPException(
            status_code=400,
            detail="Token is invalid."
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    db_user = get_user_by_id(db, decoded_data["user_id"])
    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
