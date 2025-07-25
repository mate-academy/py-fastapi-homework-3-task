from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import cast

from schemas.accounts import (
    UserRegistrationRequestSchema, UserResponseSchema,
    UserActivationSchema, PasswordResetRequestSchema,
    PasswordResetCompleteSchema, LoginRequestSchema,
    TokenRefreshRequestSchema, LoginResponseSchema,
    AccessTokenResponseSchema
)
from database import get_db

from database.models.accounts import (
    UserModel, ActivationTokenModel, PasswordResetTokenModel,
    RefreshTokenModel, UserGroupEnum
)
from uuid import uuid4

# Заглушки для core.security
def hash_password(password: str) -> str:
    return password  # НЕбезпечно, але для тестів підійде

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return plain_password == hashed_password

# Заглушка для JWTAuthManagerInterface та get_jwt_auth_manager
class DummyJWTManager:
    def create_access_token(self, user_id: int, group) -> str:
        return "dummy_access_token"

    def create_refresh_token(self, user_id: int) -> str:
        return "dummy_refresh_token"

    def decode_refresh_token(self, token: str) -> dict:
        # Припустимо, токен завжди валідний і повертає user_id=1
        return {"sub": 1}

def get_jwt_auth_manager():
    return DummyJWTManager()

# Заглушки для BaseAppSettings та get_settings
class BaseAppSettings:
    pass

def get_settings():
    return BaseAppSettings()

class JWTAuthManagerInterface:
    pass


router = APIRouter()

@router.post("/register/", response_model=UserResponseSchema, status_code=201)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter_by(email=user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=409, detail=f"User from email {user_data.email} already exists.")
    try:
        new_user = UserModel(
            email=user_data.email,
            password_hash=hash_password(user_data.password),
            is_active=False,
            group=UserGroupEnum.USER
        )
        db.add(new_user)
        db.flush()

        token = ActivationTokenModel(user_id=cast(int, new_user.id), token=str(uuid4()))
        db.add(token)
        db.commit()
        return UserResponseSchema(id=new_user.id, email=new_user.email)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while creating the user.")

@router.post("/activate/")
def activate_user(data: UserActivationSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user or user.is_active:
        raise HTTPException(status_code=400, detail="The account is already activated or not found.")

    token = db.query(ActivationTokenModel).filter_by(user_id=user.id, token=data.token).first()
    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    db.delete(token)
    db.commit()
    return {"message": "Account activated successfully."}

@router.post("/password-reset/request/")
def request_password_reset(data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter_by(user_id=user.id).delete()
        new_token = PasswordResetTokenModel(user_id=user.id, token=str(uuid4()))
        db.add(new_token)
        db.commit()
    return {"message": "If you are registered, you will be sent instructions by email."}

@router.post("/reset-password/complete/")
def complete_password_reset(data: PasswordResetCompleteSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No user with this email found")
    token_record = db.query(PasswordResetTokenModel).filter_by(user_id=user.id if user else None, token=data.token).first()

    if not user or not user.is_active or not token_record:
        if token_record:
            db.delete(token_record)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email address or token.")

    if cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        db.delete(token_record)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid email address or token.")

    try:
        user.password_hash = hash_password(data.password)
        db.delete(token_record)
        db.commit()
        return {"message": "password changed successfully"}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error resetting password.")

@router.post("/login/", response_model=LoginResponseSchema)
def login_user(
    data: LoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    user = db.query(UserModel).filter_by(email=data.email).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account not activated.")

    access_token = jwt_manager.create_access_token(user_id=user.id, group=user.group)
    refresh_token = jwt_manager.create_refresh_token(user_id=user.id)

    try:
        db.add(RefreshTokenModel(user_id=user.id, token=refresh_token))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error processing request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/api/v1/accounts/refresh/", response_model=AccessTokenResponseSchema)
def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=400, detail="The token is invalid or expired.")

    token_in_db = db.query(RefreshTokenModel).filter_by(token=data.refresh_token).first()
    if not token_in_db:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = db.query(UserModel).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(user_id=user.id, group=user.group)
    return {"access_token": access_token}
