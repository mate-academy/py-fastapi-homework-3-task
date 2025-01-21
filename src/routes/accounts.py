from datetime import datetime, timezone
from typing import cast
import random
import os

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
from schemas.accounts import (
    UserActivate,
    PasswordResetRequest,
    PasswordResetComplete,
    UserLogin,
    UserLoginSuccess,
    AccessToken,
    RefreshToken,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

from schemas.accounts import UserCreate, UserResponse
from security.passwords import hash_password
from dotenv import load_dotenv

router = APIRouter()

access_key = os.getenv("SECRET_KEY_ACCESS")
refresh_key = os.getenv("SECRET_KEY_REFRESH")
algorithm = os.getenv("JWT_SIGNING_ALGORITHM")


@router.post("/register/", response_model=UserResponse, status_code=201)
def register(
    user: UserCreate,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        user_data = db.query(UserModel).filter(UserModel.email == user.email).first()
        if user_data:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user_data.email} already exists.",
            )
        group = db.query(UserGroupModel).filter(UserGroupModel.name == "user").first()
        if not group:
            group = UserGroupModel(name=UserGroupEnum.USER.value)
            db.add(group)
            db.commit()
            db.refresh(group)
        hashed = hash_password(user.password)
        create_user = UserModel(email=user.email, password=hashed, is_active=False, group_id=group.id)
        db.add(create_user)
        db.commit()
        db.refresh(create_user)

        data = {**user.dict(), "user_id": create_user.id}

        activation_token = ActivationTokenModel(user_id=create_user.id)
        db.add(activation_token)
        db.commit()

        reset_token = PasswordResetTokenModel(user_id=create_user.id)
        db.add(reset_token)
        db.commit()
        db.refresh(reset_token)

        refr_token = jwt_manager.create_refresh_token(data=data)
        refresh_token = RefreshTokenModel(token=refr_token, user_id=create_user.id)
        create_user.refresh_tokens.append(refresh_token)
        db.add(refresh_token)
        db.commit()

        db.refresh(refresh_token)
        db.refresh(create_user)

        return {"id": create_user.id, "email": user.email}
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
def activate(data: UserActivate, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail=f"User was not found.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail=f"User account is already active.",
        )

    token = (
        db.query(ActivationTokenModel)
        .filter(ActivationTokenModel.token == data.token)
        .first()
    )

    if not token or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):        raise HTTPException(
            status_code=400,
            detail=f"Invalid or expired activation token.",
        )

    if token.user.email != data.email:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid or expired activation token.",
        )

    user.is_active = True
    db.delete(token)
    db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
def password_reset_request(data: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if user:
        try:
            reset_token = (
                db.query(PasswordResetTokenModel)
                .filter(PasswordResetTokenModel.user_id == user.id)
                .first()
            )
            db.delete(reset_token)
            db.commit()

            if user.is_active:
                reset_token = PasswordResetTokenModel(user_id=user.id)
                db.add(reset_token)
                db.commit()
                db.refresh(reset_token)
        except:
            raise HTTPException(
                status_code=400,
                detail="An error occurred while resetting the password.",
            )
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=200)
def password_reset_confirm(data: PasswordResetComplete, db: Session = Depends(get_db)):

    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()

    if (not reset_token or reset_token.token != data.token
            or datetime.now(timezone.utc) > reset_token.expires_at.replace(tzinfo=timezone.utc)):
        if reset_token:
            db.delete(reset_token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = data.password
        db.delete(reset_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post("/login/", response_model=UserLoginSuccess, status_code=201)
def login(
    data: UserLogin,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )
    if not verify_password(data.password, user._hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )
    try:
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id, "email": user.email})
        db_refresh_token = RefreshTokenModel(token=refresh_token, user_id=user.id)
        db.add(db_refresh_token)
        db.commit()
        db.refresh(db_refresh_token)
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": db_refresh_token.token,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=AccessToken, status_code=200)
def refresh(
    data: RefreshToken,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        refresh_token = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = refresh_token["user_id"]
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    expected_refresh_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == data.refresh_token).first()

    if not expected_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {
        "access_token": access_token
    }
