from datetime import timezone, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import get_db
from security import token_manager
from src.database.models.accounts import UserModel, UserGroupModel, UserGroupEnum, RefreshTokenModel, \
    ActivationTokenModel, PasswordResetTokenModel
from src.schemas.accounts import UserCreate, UserOut, Token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", status_code=201)
async def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserModel).filter(UserModel.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="User already exists")

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

    return {"message": "User created. Please check your email to activate account."}


@router.post("/activate")
async def activate_account(token: str, db: Session = Depends(get_db)):
    act_token = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == token).first()

    if not act_token or act_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    act_token.user.is_active = True
    db.delete(act_token)
    db.commit()
    return {"message": "Account activated!"}


@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == form_data.username).first()

    if not user or not user.verify_password(form_data.password):
        raise HTTPException(status_code=401, detail="Wrong email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Activate your account first")

    access_token = token_manager.create_access_token(subject=user.email)
    refresh_token_str = token_manager.create_refresh_token(subject=user.email)

    db_refresh = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=7,
        token=refresh_token_str
    )
    db.add(db_refresh)
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token_str, "token_type": "bearer"}


@router.post("/refresh")
async def refresh_access(refresh_token: str, db: Session = Depends(get_db)):
    db_token = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == refresh_token).first()

    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

    new_access = token_manager.create_access_token(subject=db_token.user.email)

    return {"access_token": new_access, "token_type": "bearer"}


@router.post("/password-reset-request")
async def request_reset(email: str, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if user:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()
    return {"message": "If email exists, instructions were sent."}


@router.post("/password-reset-complete")
async def complete_reset(token: str, new_password: str, db: Session = Depends(get_db)):
    reset_token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == token).first()

    if not reset_token or reset_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid token")

    reset_token.user.password = new_password
    db.delete(reset_token)
    db.commit()
    return {"message": "Password updated successfully."}
