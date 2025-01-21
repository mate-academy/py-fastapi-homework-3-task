import time
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import ExpiredSignatureError
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
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager

router = APIRouter()

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def register(
        register_data: UserRegistrationRequestSchema,
        db: Session = Depends(get_db),
):
    user_exist = db.query(UserModel).filter_by(email=register_data.email).first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {register_data.email} already exists."
        )

    group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

    try:
        user = UserModel.create(
            email=register_data.email,
            raw_password=register_data.password,
            group_id=group.id,
        )
        db.add(user)
        db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        db.commit()
        db.refresh(user)

        return user
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
def activate(
        activate_data: UserActivationRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=activate_data.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A user with this email {activate_data.email} does not exist."
        )

    activation_token = db.query(ActivationTokenModel).filter_by(user_id=user.id).first()
    if (
            not activation_token or
            activation_token.expires_at <= datetime.now() or
            activation_token.token != activate_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or expired activation token."
            # detail=f"Invalid or expired activation token. token: {activation_token.token}, get {activate_data.token}"
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    db.delete(activation_token)

    db.commit()

    return {
        "message":  "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
def request_password_reset(
        reset_user: PasswordResetRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=reset_user.email).first()
    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter_by(user_id=user.id).delete()
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
def reset_password(
        reset_user: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=reset_user.email).join(PasswordResetTokenModel).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    try:
        for token in db.query(PasswordResetTokenModel).filter_by(user_id=user.id).all():
            if token.expires_at <= datetime.now():
                db.delete(token)
        db.commit()

        token = (
            db
            .query(PasswordResetTokenModel)
            .filter_by(user_id=user.id, token=reset_user.token)
            .first()
        )
        if not token:
            for token in db.query(PasswordResetTokenModel).filter_by(user_id=user.id).all():
                    db.delete(token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = reset_user.password
        db.delete(token)
        db.commit()
        return {
            "message": "Password reset successfully."
        }
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def login(
        user_data: UserLoginRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()
    if (
        not user or
        not user.verify_password(user_data.password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    data = {
        "user_id": user.id,
    }
    try:
        access_token_str = jwt_auth_manager.create_access_token(data)
        refresh_token_str = jwt_auth_manager.create_refresh_token(data)
        refresh_token = RefreshTokenModel(user_id=user.id, token=refresh_token_str)
        db.add(refresh_token)
        db.commit()
        return {
            "access_token": access_token_str,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
def refresh(
        data: TokenRefreshRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db),
):
    try:
        read = jwt_auth_manager.decode_refresh_token(data.refresh_token)
        user = db.get(UserModel, read["user_id"])

        token = db.query(RefreshTokenModel).filter_by(token=data.refresh_token).first()

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        access_token = jwt_auth_manager.create_access_token(read)
        return {
            "access_token": access_token,
        }
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
