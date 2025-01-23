from datetime import datetime, timezone

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
from schemas.accounts import UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema, \
    UserActivationRequestSchema, MessageResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema
from security.interfaces import JWTAuthManagerInterface
from src.schemas.accounts import UserRegistrationRequestSchema, UserRegistrationResponseSchema

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
def register(register_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    user_exist = db.query(UserModel).filter(UserModel.email == register_data.email).first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {register_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()

    try:
        user = UserModel.create(
            email=register_data.email,
            raw_password=register_data.password,
            group_id=user_group.id
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


@router.post("/login/", status_code=201)
def login(
        user_data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if not user or not user.verify_password(raw_password=user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_auth_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_auth_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token_instance = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_instance)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh(
        refresh_token_data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decode_token = jwt_auth_manager.decode_refresh_token(refresh_token_data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    refresh_token = db.query(RefreshTokenModel).filter(
        RefreshTokenModel.token == refresh_token_data.refresh_token).first()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter(UserModel.id == decode_token["user_id"]).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_auth_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)


@router.post("/activate/", response_model=MessageResponseSchema)
def activate(user_data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    activation_token = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == user_data.token).first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expired_at = activation_token.expires_at

    if expired_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(activation_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user.is_active = True
    db.delete(activation_token)
    db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
def reset(user_data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if user and user.is_active:
        token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()

        if token:
            db.delete(token)

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
def reset_password(
        user_data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if not user or not user.is_active:
        token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == user_data.token).first()
        if token:
            db.delete(token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == user_data.token).first()
    if not reset_token:
        token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()
        if token:
            db.delete(token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    expired_at = reset_token.expires_at

    if expired_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = user_data.password
        db.delete(reset_token)
        db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
