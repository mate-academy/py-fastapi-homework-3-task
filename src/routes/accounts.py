from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import ExpiredSignatureError, JWTError
from pytz import utc
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
from exceptions import BaseSecurityError, TokenExpiredError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema, UserActivationRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
def register(register_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    user_exist = db.query(UserModel).filter_by(email=register_data.email).first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {register_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

    try:
        user = UserModel.create(
            email=register_data.email,
            raw_password=register_data.password,
            group_id=user_group.id
        )
        db.add(user)
        db.flush()
        db.refresh(user)

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        db.commit()
        db.refresh(user)

    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return {
        "id": user.id,
        "email": user.email
    }


@router.post("/activate/")
def activate_user(activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter_by(email=activation_data.email).first()

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    if not user.activation_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if (
        utc.localize(user.activation_token.expires_at) < datetime.now(timezone.utc)
        or user.activation_token.token != activation_data.token
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    user.activation_token = None

    db.commit()
    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/")
def password_reset_request(data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if user and user.is_active:
        if user.password_reset_token:
            db.delete(user.password_reset_token)
        password_reset_token = PasswordResetTokenModel(
            token=generate_secure_token(),
            user=user,
        )
        db.add(password_reset_token)
        user.password_reset_token = password_reset_token
        db.commit()
        db.refresh(user)

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
def password_reset_completion(
        data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if not (
        user.password_reset_token
        and user.password_reset_token.token == data.token
        and utc.localize(user.password_reset_token.expires_at) > datetime.now(timezone.utc)
    ):
        if user.password_reset_token:
            db.delete(user.password_reset_token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = data.password
        db.delete(user.password_reset_token)
        db.commit()

    except SQLAlchemyError:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
def login(
        data: UserLoginRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter_by(email=data.email).first()

    if not user or not user.verify_password(data.password):
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
        access_token = jwt_auth_manager.create_access_token({"user_id": user.id})
        refresh_token = RefreshTokenModel(
            user=user,
            token=jwt_auth_manager.create_refresh_token({"user_id": user.id})
        )
        db.add(refresh_token)
        db.commit()
        db.refresh(refresh_token)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer"
        }

    except SQLAlchemyError:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh(
        data: TokenRefreshRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db)
):
    try:
        jwt_auth_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    token = db.query(RefreshTokenModel).filter_by(token=data.refresh_token).first()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if not token.user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    return {
        "access_token": jwt_auth_manager.create_access_token({"user_id": token.user.id})
    }
