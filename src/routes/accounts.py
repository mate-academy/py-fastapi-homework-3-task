from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserActivationResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
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

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exist."
        )
    hashed_password = hash_password(user_data.password)

    new_user = UserModel(
        email=user_data.email,
        hashed_password=hashed_password,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        group_id=db.query(UserModel).filter(UserGroupModel.name == "USER").first().id
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    activation_token = ActivationTokenModel(
        token="some_generated_token",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        user_id=new_user.id
    )
    db.add(activation_token)
    db.commit()
    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post("/activate/", response_model=UserActivationResponseSchema)
def activate_user(activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == activation_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_record = db.query(ActivationTokenModel).filter(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token
    ).first()

    if not token_record or token_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    db.delete(token_record)
    db.commit()

    return UserActivationResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=PasswordResetResponseSchema)
def request_password_reset(request_data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == request_data.email).first()

    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()

        reset_token = PasswordResetTokenModel(
            token="some_generated_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user_id=user.id
        )
        db.add(reset_token)
        db.commit()

    return PasswordResetResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=PasswordResetCompleteResponseSchema)
def complete_password_reset(reset_data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == reset_data.email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_record = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == reset_data.token
    ).first()

    if not token_record or token_record.expires_at < datetime.now(timezone.utc):
        if token_record:
            db.delete(token_record)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    user.hashed_password = hash_password(reset_data.password)
    db.delete(token_record)
    db.commit()

    return PasswordResetCompleteResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema)
def login_user(login_data: UserLoginRequestSchema, db: Session = Depends(get_db),
               jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    user = db.query(UserModel).filter(UserModel.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(data={"sub": user.email})
    refresh_token = jwt_manager.create_refresh_token(data={"sub": user.email})

    new_refresh_token = RefreshTokenModel(
        token=refresh_token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=get_settings().LOGIN_TIME_DAYS),
        user_id=user.id
    )
    db.add(new_refresh_token)
    db.commit()

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post("/api/v1/accounts/refresh/", response_model=TokenRefreshResponseSchema)
def refresh_access_token(refresh_data: TokenRefreshRequestSchema, db: Session = Depends(get_db),
                         jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        email = payload.get("sub")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    token_record = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == refresh_data.refresh_token).first()
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"sub": user.email})

    return TokenRefreshResponseSchema(access_token=access_token)
