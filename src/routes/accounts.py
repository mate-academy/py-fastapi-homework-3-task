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

from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter_by(email=user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()
    new_user = UserModel(
        email=user_data.email,
        password=user_data.password,
        group=user_group
    )
    activation_token = ActivationTokenModel(user=new_user)

    try:
        db.add(new_user)
        db.add(activation_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return UserRegistrationResponseSchema(
        id=new_user.id,
        email=new_user.email
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=200
)
def activate_user(activation_data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter_by(email=activation_data.email).first()
    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    activation_token = db.query(ActivationTokenModel).filter_by(user=db_user).first()
    if not activation_token or datetime.now(timezone.utc) > activation_token.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    try:
        db_user.is_active = True
        db.delete(activation_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during account activation.")

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200
)
def password_reset_request(reset_data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter_by(email=reset_data.email).first()

    if db_user and db_user.is_active:
        try:
            if db_user.password_reset_token:
                db.delete(db_user.password_reset_token)
            new_password_reset_token = PasswordResetTokenModel(user=db_user)
            db.add(new_password_reset_token)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(status_code=500, detail="An error occurred during account password reset.")

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200
)
def password_reset_complete(reset_data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    db_user = db.query(UserModel).filter_by(email=reset_data.email).first()
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token = db.query(PasswordResetTokenModel).filter_by(user=db_user).first()
    if not reset_token or reset_data.token != reset_token.token or datetime.now(timezone.utc) > reset_token.expires_at.replace(tzinfo=timezone.utc):
        if reset_token:
            db.delete(reset_token)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = reset_data.password
        db.delete(reset_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return MessageResponseSchema(
        message="Password reset successfully."
    )
