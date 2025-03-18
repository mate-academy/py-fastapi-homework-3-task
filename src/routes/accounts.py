from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

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
from database.models.email_service import send_email
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password, hash_password
from security.token_manager import JWTAuthManager
from security.utils import generate_activation_token, send_reset_email

router = APIRouter()


class ActivationRequest(BaseModel):
    email: str
    token: str


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetCompletion(BaseModel):
    email: str
    token: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserRegisterRequest(BaseModel):
    email: str
    password: str


@router.post("/activate/")
async def activate_account(request: ActivationRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    token = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == request.token).first()
    if not token or token.user.email != request.email or token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    db.delete(token)
    db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def password_reset_request(request: PasswordResetRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
        reset_token = PasswordResetTokenModel(user_id=user.id, token=generate_activation_token(),
                                              expires_at=datetime.utcnow() + timedelta(hours=1))
        db.add(reset_token)
        db.commit()

    send_reset_email(request.email)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def complete_password_reset(request: PasswordResetCompletion, db: Session = Depends(get_db)) -> dict[str, str]:
    token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == request.token).first()
    if not token or token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="User not found.")

    user.password = request.password
    db.delete(token)
    db.commit()

    return {"message": "Password reset successfully."}


@router.post("/login/")
async def login(request: LoginRequest, db: Session = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)) -> dict[str, str]:
    user = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not user or not verify_password(request.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(user.id)
    refresh_token = jwt_manager.create_refresh_token(user.id)

    db.add(RefreshTokenModel(user_id=user.id, token=refresh_token))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/api/v1/accounts/refresh/")
async def refresh_access_token(request: RefreshTokenRequest, db: Session = Depends(get_db),
                               jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)) -> dict[str, str]:
    refresh_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == request.refresh_token).first()
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = db.query(UserModel).filter(UserModel.id == refresh_token.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(user.id)

    return {"access_token": access_token}


jwt_manager = JWTAuthManager(secret_key_access="secret_key", secret_key_refresh="refresh_key", algorithm="HS256")


@router.post("/register")
async def register(user: UserRegisterRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    existing_user = db.query(UserModel).filter(UserModel.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already in use")

    hashed_password = hash_password(user.password)

    new_user = UserModel(email=user.email, _hashed_password=hashed_password, is_active=False)
    db.add(new_user)
    db.commit()

    activation_token = jwt_manager.create_access_token(data={"email": user.email}, expires_delta=timedelta(hours=1))

    activation_link = f"https: //example.com/activate/{activation_token}"

    send_email(
        subject="Activate your account",
        body=f"To activate your account, please follow this link: {activation_link}",
        to_email=user.email,
        from_email="your_email@example.com",
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        smtp_user="your_email@example.com",
        smtp_password="your_email_password",
        html=True
    )

    return {"message": "Please check your email to activate your account."}
