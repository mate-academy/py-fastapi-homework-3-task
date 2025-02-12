from datetime import datetime, timezone
from typing import cast

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
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema

)
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token
from exceptions.security import TokenExpiredError

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
def register(
        user_data: UserRegistrationRequestSchema,
        db: Session = Depends(get_db)
):
    users = db.query(UserModel).filter_by(email=user_data.email).all()
    if not users:
        try:
            hashed = hash_password(user_data.password)
            role = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

            user = UserModel(email=user_data.email, _hashed_password=hashed, group=role)
            db.add(user)
            db.commit()
            db.refresh(user)

            activation_token = ActivationTokenModel(user_id=user.id)
            db.add(activation_token)
            db.commit()
            db.refresh(activation_token)

            return user

        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    raise HTTPException(
        status_code=409,
        detail=f"A user with this email {user_data.email} already exists."
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=200
)
def activation(
        user_data: UserActivationRequestSchema,
        db: Session = Depends(get_db)
):

    email = user_data.email
    user = db.query(UserModel).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    token = user_data.token
    activation_token = db.query(ActivationTokenModel).filter_by(token=token).first()

    if (
            not activation_token
            or activation_token.user.email != email
            or activation_token.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    db.commit()
    db.refresh(user)

    db.delete(activation_token)
    db.commit()

    return {
        "message": "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200
)
def password_reset_request(
        data: PasswordResetRequestSchema,
        db: Session = Depends(get_db)
):

    user = db.query(UserModel).filter_by(email=data.email).first()
    if user and user.is_active:

        password_reset_token = user.password_reset_token
        if password_reset_token:
            db.delete(password_reset_token)
            db.commit()

        password_reset_token = PasswordResetTokenModel(
            user_id=user.id,
            token=generate_secure_token()
        )
        db.add(password_reset_token)
        db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200
)
def password_reset_complete(
        data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db)
):

    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).first()
    if (
            not reset_token
            or reset_token.token != data.token
            or reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        if reset_token:
            db.delete(reset_token)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        hashed_password = hash_password(data.password)
        user._hashed_password = hashed_password

        db.delete(reset_token)
        db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
def login(
        data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    try:
        refresh_token_entry = RefreshTokenModel(user_id=user.id, token=refresh_token)
        db.add(refresh_token_entry)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh(
        data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        refresh_token_data = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token = db.query(RefreshTokenModel).filter_by(token=data.refresh_token).first()
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = db.query(UserModel).filter_by(id=refresh_token_data["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": refresh_token_data["user_id"]})

    return {"access_token": access_token}
