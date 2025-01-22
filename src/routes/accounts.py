from datetime import datetime, timezone
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
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema, PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema, UserLoginResponseSchema,
    UserLoginRequestSchema, TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)

router = APIRouter()


@router.post(
    "/register",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
def register(
        user: UserRegistrationRequestSchema,
        db: Session = Depends(get_db)
):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter(
        UserGroupModel.name == UserGroupEnum.USER).first()
    try:
        user = UserModel.create(email=user.email, raw_password=user.password,
                                group_id=user_group.id)
        db.add(user)
        db.flush()
        db.refresh(user)

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        db.commit()

        return user
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate",
    response_model=MessageResponseSchema
)
def activate(
        user: UserActivationRequestSchema,
        db: Session = Depends(get_db)
):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token = db.query(ActivationTokenModel).filter(
        ActivationTokenModel.token == user.token).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        db.delete(token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    db_user.is_active = True
    db.delete(token)
    db.commit()
    return MessageResponseSchema(
        message="User account activated successfully.")


@router.post(
    "/password-reset/request",
    response_model=MessageResponseSchema
)
def password_reset_request(
        user: PasswordResetRequestSchema,
        db: Session = Depends(get_db)
):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if db_user and db_user.is_active:
        token = (
            db.query(PasswordResetTokenModel).filter(
                PasswordResetTokenModel.user_id == db_user.id).first()
        )
        if token:
            db.delete(token)

        reset_token = PasswordResetTokenModel(user_id=cast(int, db_user.id))
        db.add(reset_token)
        db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete",
    response_model=MessageResponseSchema
)
def password_reset_complete(
        user: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db)
):
    db_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if not db_user or not db_user.is_active:
        token = db.query(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.token == user.token).first()
        if token:
            db.delete(token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.token == user.token).first()
    if not reset_token:
        token = db.query(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.user_id == db_user.id).first()
        if token:
            db.delete(token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, reset_token.expires_at).replace(
        tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        db_user.password = user.password
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
    "/login",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
def login(
        user_data: UserLoginRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(
            get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
        db: Session = Depends(get_db)
):
    db_user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not db_user or not db_user.verify_password(
            raw_password=user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_auth_manager.create_access_token(
            {"user_id": db_user.id}
        )
        refresh_token = jwt_auth_manager.create_refresh_token(
            {"user_id": db_user.id}
        )
        db_refresh = RefreshTokenModel.create(
            user_id=cast(int, db_user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh)
        db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponseSchema
)
def refresh(
        token_data: TokenRefreshRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(
            get_jwt_auth_manager),
        db: Session = Depends(get_db)
):
    try:
        token_decode = jwt_auth_manager.decode_refresh_token(
            token_data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    refresh_token = (
        db.query(RefreshTokenModel).filter(
            RefreshTokenModel.token == token_data.refresh_token).first()
    )
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter(
        UserModel.id == token_decode["user_id"]).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")

    access_token = jwt_auth_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
