from datetime import datetime, timezone
from typing import cast
import pytz

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
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)


router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
def register(
    user_data: UserRegistrationRequestSchema,
    db: Session = Depends(get_db)
) -> UserRegistrationRequestSchema:
    user_exists = db.query(UserModel).filter_by(email=user_data.email).first()

    if user_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    hashed_password = hash_password(user_data.password)

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

    new_user = UserModel(
        email=user_data.email,
        _hashed_password=hashed_password,
        group=user_group
    )

    activation_token = ActivationTokenModel(user=new_user)

    try:
        db.add(new_user)
        db.add(activation_token)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(
        id=new_user.id,
        email=new_user.email
    )


@router.post("/activate/", response_model=MessageResponseSchema)
def activate_account(
    user_data: UserActivationRequestSchema,
    db: Session = Depends(get_db)
) -> MessageResponseSchema:
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found."
        )

    activation_token = db.query(ActivationTokenModel).filter_by(user=user).first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = activation_token.expires_at.astimezone(pytz.UTC)

    if expires_at < datetime.now(pytz.UTC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = activation_token.user

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True

    try:
        db.delete(activation_token)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
def reset_password_request(
    user_data: PasswordResetRequestSchema,
    db: Session = Depends(get_db)
) -> MessageResponseSchema:
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter_by(user=user).delete()

        new_reset_token = PasswordResetTokenModel(user=user)
        db.add(new_reset_token)
        db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
def reset_password_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db)
) -> MessageResponseSchema:
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token = db.query(PasswordResetTokenModel).filter_by(user=user).first()

    expires_at = reset_token.expires_at.astimezone(pytz.UTC)

    if user_data.token != reset_token.token or expires_at < datetime.now(pytz.UTC):
        if reset_token:
            db.delete(reset_token)
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user._hashed_password = hash_password(user_data.password)
        db.commit()

        db.delete(reset_token)
        db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
def login(
    user_data: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
) -> UserLoginResponseSchema:
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user or not user.verify_password(user_data.password):
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
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    try:
        refresh_token_record = RefreshTokenModel(user=user, token=refresh_token)
        db.add(refresh_token_record)
        db.commit()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    token_type = "bearer"

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=token_type
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh_token(
    token_request_data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    try:
        token_data = jwt_manager.decode_refresh_token(token_request_data.refresh_token)
        user_id = token_data["user_id"]
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    expected_refresh_token = db.query(RefreshTokenModel).filter_by(
        token=token_request_data.refresh_token
    ).first()

    if not expected_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
