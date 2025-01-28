from datetime import datetime, timezone, tzinfo

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager
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
from schemas import (
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema, UserRegistrationResponseSchema
)
from schemas.accounts import PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

@router.post("/register/", response_model=UserRegistrationResponseSchema,status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == user_data.email).first()

    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    email = user_data.email
    password = hash_password(user_data.password)

    try:
        group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
        if not group:
            group = UserGroupModel(name=UserGroupEnum.USER)
            db.flush()
            db.refresh(group)

        new_user = UserModel(
            email=email,
            password=password,
            group_id=group.id,
            group=group
        )
        db.add(new_user)
        db.flush()
        db.refresh(new_user)
        activation_token = ActivationTokenModel(
            user_id=new_user.id,
            user=new_user
        )
        db.add(activation_token)
        db.flush()
        db.refresh(activation_token)
        new_user.activation_token = activation_token

        db.commit()

        return new_user
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred during user creation."
        )



@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def activate_account(data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    activation_token = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == data.token).first()

    if not activation_token or datetime.now(timezone.utc) > activation_token.expires_at.replace(tzinfo=timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if activation_token.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    activation_token.user.is_active = True
    db.commit()

    db.delete(activation_token)
    db.commit()

    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def create_reset_token(data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()

    new_reset_token = PasswordResetTokenModel(user_id=user.id)

    db.add(new_reset_token)
    db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def reset_password(data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expected_token = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()

    if (not expected_token or expected_token.token != data.token
            or datetime.now(timezone.utc) > expected_token.expires_at.replace(tzinfo=timezone.utc)):
        if expected_token:
            db.delete(expected_token)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = data.password
        db.delete(expected_token)
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


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
def login_user(
        data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token_str
        )
        db.add(refresh_token)
        db.commit()

        access_token = jwt_manager.create_access_token({"user_id": user.id})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token.token,
            "token_type": "bearer"
        }

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
def token_refresh(
        data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        token_data = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = token_data["user_id"]
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
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


