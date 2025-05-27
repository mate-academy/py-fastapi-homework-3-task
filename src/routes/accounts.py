from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing import cast

from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from database import UserModel, ActivationTokenModel, UserGroupEnum, PasswordResetTokenModel, RefreshTokenModel
from database.session_postgresql import get_postgresql_db
from schemas.accounts import UserRegistrationRequestSchema, UserResponseSchema, ActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteSchema, LoginRequestSchema, TokenRefreshSchema
from security.interfaces import JWTAuthManagerInterface
from utils.password import Hasher
from utils.token import generate_token

router = APIRouter()

@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_postgresql_db)):
    try:
        existing_user = db.query(UserModel).filter(UserModel.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        hashed_password = Hasher.get_password_hash(user_data.password)


        new_user = UserModel(
            email=user_data.email,
            password=hashed_password,
            group=UserGroupEnum.USER,
            is_active=False
        )
        db.add(new_user)
        db.flush()


        token = generate_token()
        activation_token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=token,
            expires_at=datetime.utcnow() + timedelta(days=1)
        )
        db.add(activation_token)
        db.commit()

        return UserResponseSchema(id=new_user.id, email=new_user.email)

    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

@router.post("/activate/")
def activate_user(data: ActivationRequestSchema, db: Session = Depends(get_postgresql_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = db.query(ActivationTokenModel).filter(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == data.token
    ).first()

    if not token or cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    db.delete(token)
    db.commit()
    return {"message": "User account activated successfully."}

@router.post("/password-reset/request/")
def request_password_reset(data: PasswordResetRequestSchema, db: Session = Depends(get_postgresql_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()

        token = generate_token()
        reset_token = PasswordResetTokenModel(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.add(reset_token)
        db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}

@router.post("/reset-password/complete/")
def reset_password(data: PasswordResetCompleteSchema, db: Session = Depends(get_postgresql_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_record = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == data.token
    ).first()

    if not token_record or cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        if token_record:
            db.delete(token_record)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = Hasher.get_password_hash(data.password)
        db.delete(token_record)
        db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

@router.post("/login/")
def login_user(
    data: LoginRequestSchema,
    db: Session = Depends(get_postgresql_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not Hasher.verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(user_id=user.id)
        refresh_token = jwt_manager.create_refresh_token(user_id=user.id)

        RefreshTokenModel.create(db=db, user_id=user.id, token=refresh_token)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/api/v1/accounts/refresh/")
def refresh_token(
    data: TokenRefreshSchema,
    db: Session = Depends(get_postgresql_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(status_code=400, detail="Token has expired.")

        token_record = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == data.refresh_token).first()
        if not token_record:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        new_access_token = jwt_manager.create_access_token(user_id=user.id)
        return {"access_token": new_access_token}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")
