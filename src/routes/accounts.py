from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
# from sqlalchemy.sql.functions import user

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
from schemas import (
    UserRegistrationRequestSchema, UserRegistrationResponseSchema, UserActivationRequestSchema,
    MessageResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema,
    UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
    user = UserModel.create(user_data.email, user_data.password, group.id)

    try:
        db.add(user)
        db.flush()

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

    return user


@router.post("/activate/", response_model=MessageResponseSchema)
def activate_user(user_data: UserActivationRequestSchema, db: Session = Depends(get_db)) -> MessageResponseSchema:

    db_token = (
        db.query(ActivationTokenModel)
        .join(UserModel)
        .filter(
            ActivationTokenModel.token == user_data.token,
            UserModel.email == user_data.email
        )
        .first()
    )

    # expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)
    if not db_token or cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    user = db_token.user
    if not user or user.is_active or user.activation_token.token != db_token.token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    try:
        user.is_active = True
        db.flush()
        db.delete(db_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user activation."
        )

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
def password_reset_request(
        user_data: PasswordResetRequestSchema,
        db: Session = Depends(get_db)
) -> MessageResponseSchema:
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if user and user.is_active:
        try:
            db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user == user).delete()
            db.flush()
            new_token = PasswordResetTokenModel(user_id=user.id)
            db.add(new_token)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user activation."
            )

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
def password_reset_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db)
) -> MessageResponseSchema:
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    db_token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user == user).first()
    if not db_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    is_bad_token = (db_token.token != user_data.token
                    or cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc))

    try:
        db.delete(db_token)
        db.flush()
        if is_bad_token:
            db.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")
        user.password = user_data.password
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
def login(
        user_data: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
        db: Session = Depends(get_db)
) -> UserLoginResponseSchema:
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})
    db_refresh_token = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )

    try:
        db.add(db_refresh_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=db_refresh_token.token,
        token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh(
        user_data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db)
) -> TokenRefreshResponseSchema:
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")

    db_refresh_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == user_data.refresh_token).first()
    if not db_refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user = db.query(UserModel).filter(UserModel.id == decoded_refresh_token.get("user_id")).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
