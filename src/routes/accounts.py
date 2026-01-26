from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from src.database import get_db
from src.security import token_manager
from src.database.models.accounts import (
    UserModel, UserGroupModel, UserGroupEnum,
    ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
)
from src.schemas.accounts import (
    UserRegistrationRequestSchema, UserRegistrationResponseSchema,
    UserActivationRequestSchema, MessageResponseSchema,
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema, UserLoginResponseSchema,
    TokenRefreshRequestSchema, TokenRefreshResponseSchema
)

router = APIRouter(prefix="/api/v1/accounts", tags=["Authentication"])


# 1. Implementation User Registration Endpoint
@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    if db.query(UserModel).filter(UserModel.email == user_in.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists."
        )

    user_group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()

    new_user = UserModel.create(
        email=user_in.email,
        raw_password=user_in.password,
        group_id=user_group.id
    )
    db.add(new_user)
    db.flush()

    activation = ActivationTokenModel(user_id=new_user.id)
    db.add(activation)
    db.commit()
    db.refresh(new_user)

    return new_user


# 2. Implementation User Account Activation Endpoint
@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="Account is already active.")

    act_token = db.query(ActivationTokenModel).filter(
        ActivationTokenModel.token == data.token,
        ActivationTokenModel.user_id == user.id
    ).first()

    if not act_token or act_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired token.")

    user.is_active = True
    db.delete(act_token)
    db.commit()
    return {"message": "User account activated successfully."}


# 3. Implementation User Login Endpoint
@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(data: UserLoginRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not activated.")

    access_token = token_manager.create_access_token(subject=user.email)
    refresh_token_str = token_manager.create_refresh_token(subject=user.email)

    db_refresh = RefreshTokenModel.create(user_id=user.id, days_valid=7, token=refresh_token_str)
    db.add(db_refresh)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_str,
        "token_type": "bearer"
    }


# 4. Implementation Access Token Refresh Endpoint
@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access(data: TokenRefreshRequestSchema, db: Session = Depends(get_db)):
    db_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == data.refresh_token).first()

    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired refresh token.")

    user = db_token.user
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access = token_manager.create_access_token(subject=user.email)
    return {
        "access_token": new_access,
        "refresh_token": data.refresh_token,
        "token_type": "bearer"
    }


# 5. Implementation Password Reset Token Request Endpoint
@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_reset(data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if user:
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is inactive.")

        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


# 6. Implementation Password Reset Completion Endpoint
@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_reset(data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    reset_token = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.token == data.token,
        PasswordResetTokenModel.user_id == user.id
    ).first()

    if not reset_token or reset_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token.")

    # user.password = hash_password(data.password)
    user.password = data.password

    db.delete(reset_token)
    db.commit()
    return {"message": "Password reset successfully."}
