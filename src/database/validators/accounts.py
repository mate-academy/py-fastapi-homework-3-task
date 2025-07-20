import re
import email_validator
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from dependencies import get_db, get_settings, get_jwt_auth_manager
from models import UserModel, PasswordResetTokenModel, RefreshTokenModel
from schemas import PasswordResetRequest, PasswordResetComplete, RefreshTokenRequest, TokenResponse
from utils import send_password_reset_email
from settings import BaseAppSettings
from jwt_manager import JWTAuthManagerInterface

router = APIRouter()


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r'\d', password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r'[@$!%*?&#]', password):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
    return password


def validate_email(user_email: str) -> str:
    try:
        email_info = email_validator.validate_email(user_email, check_deliverability=False)
        email = email_info.normalized
    except email_validator.EmailNotValidError as error:
        raise ValueError(str(error))
    return email


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
def request_password_reset(
        reset_request: PasswordResetRequest,
        db: Session = Depends(get_db)
):
    try:
        email = validate_email(reset_request.email)
    except ValueError:
        return {"message": "If you are registered, you will receive an email with instructions."}

    user = db.query(UserModel).filter(UserModel.email == email).first()

    if user and user.is_active:
        # Delete existing tokens
        db.query(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.user_id == user.id
        ).delete(synchronize_session=False)

        # Create and save new token
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

        # Send password reset email
        send_password_reset_email(email, reset_token.token)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
def complete_password_reset(
        reset_data: PasswordResetComplete,
        db: Session = Depends(get_db)
):
    # Validate email format
    try:
        email = validate_email(reset_data.email)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )

    # Validate password strength
    try:
        validate_password_strength(reset_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        # Don't reveal if user doesn't exist
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is not active"
        )

    token_record = db.query(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == reset_data.token
    ).first()

    # Check token validity
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token"
        )

    if token_record.expires_at < datetime.utcnow():
        db.delete(token_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token"
        )

    # Update password and clean up
    try:
        user.set_password(reset_data.password)
        db.delete(token_record)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=TokenResponse)
def login_user(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = db.query(UserModel).filter(UserModel.email == form_data.username).first()

    # Validate credentials
    if not user or not user.verify_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Check account activation
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    # Create tokens
    access_token = jwt_manager.create_access_token(user.id)
    refresh_token = jwt_manager.create_refresh_token(user.id)

    # Store refresh token in database
    try:
        expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        db_refresh_token = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token,
            expires_at=expires_at
        )
        db.add(db_refresh_token)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/api/v1/accounts/refresh/")
def refresh_access_token(
        token_data: RefreshTokenRequest,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )

    # Check token existence in database
    db_token = db.query(RefreshTokenModel).filter(
        RefreshTokenModel.token == token_data.refresh_token
    ).first()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found"
        )

    # Validate user existence
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Generate new access token
    access_token = jwt_manager.create_access_token(user_id)
    return {"access_token": access_token}