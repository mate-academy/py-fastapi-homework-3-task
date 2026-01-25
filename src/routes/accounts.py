from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from database import get_db
from security import token_manager
from src.database.models.accounts import (
    UserModel, UserGroupModel, UserGroupEnum,
    ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
)
from schemas.accounts import (
    UserCreate, UserOut, AccountActivationRequest,
    PasswordResetRequest, PasswordResetCompleteRequest,
    LoginRequest, TokenRefreshRequest, TokenResponse
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# 1. Registration
@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
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


# 2. Activation
@router.post("/activate")
async def activate_account(data: AccountActivationRequest, db: Session = Depends(get_db)):
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


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: Session = Depends(get_db)):
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

    return {"access_token": access_token, "refresh_token": refresh_token_str, "token_type": "bearer"}


# 4. Refresh Token (JSON payload)
@router.post("/refresh", response_model=TokenResponse)
async def refresh_access(data: TokenRefreshRequest, db: Session = Depends(get_db)):
    db_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == data.refresh_token).first()

    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    new_access = token_manager.create_access_token(subject=db_token.user.email)
    return {"access_token": new_access, "refresh_token": data.refresh_token, "token_type": "bearer"}


# 5. Password Reset Request
@router.post("/password-reset/request")
async def request_reset(data: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


# 6. Password Reset Complete
@router.post("/password-reset/complete")
async def complete_reset(data: PasswordResetCompleteRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    reset_token = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.token == data.token,
        PasswordResetTokenModel.user_id == user.id
    ).first()

    if not reset_token or reset_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid token.")

    user.password = data.new_password

    db.delete(reset_token)
    db.commit()
    return {"message": "Password reset successfully."}
