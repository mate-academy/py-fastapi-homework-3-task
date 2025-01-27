from datetime import datetime

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
from exceptions.security import TokenExpiredError
from security.interfaces import JWTAuthManagerInterface

from src.schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

from src.security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
def register(data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(UserModel).filter(UserModel.email == data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {data.email} already exists."
            )

        hashed_password = hash_password(data.password)

        user_group = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        new_user = UserModel(email=data.email, password=hashed_password, group=user_group)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        db.commit()
        db.refresh(activation_token)

        return {
            "id": new_user.id,
            "email": new_user.email,
            "password": data.password
        }

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def activate_account(data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    try:
        user = db.query(UserModel).filter(UserModel.email == data.email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found."
            )

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active."
            )

        token = db.query(ActivationTokenModel).filter(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token,
        ).first()

        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        if datetime.now() > token.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        user.is_active = True
        db.delete(token)
        db.commit()

        return MessageResponseSchema(message="User account activated successfully.")

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def request_password_reset(data: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    try:
        standard = MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

        user = db.query(UserModel).filter(UserModel.email == data.email).first()

        if not user or not user.is_active:
            return standard

        db.query(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.user_id == user.id
        ).delete()

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

        return standard

    except SQLAlchemyError:
        db.rollback()
        return standard


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def complete_password_reset(data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    try:
        user = db.query(UserModel).filter(UserModel.email == data.email).join(PasswordResetTokenModel).first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        for token in db.query(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.user_id == user.id
        ).all():
            if token.expires_at <= datetime.now():
                db.delete(token)
        db.commit()

        token = (
            db.query(PasswordResetTokenModel)
            .filter(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == data.token
            )
            .first()
        )

        if not token:
            for t in db.query(PasswordResetTokenModel).filter(
                PasswordResetTokenModel.user_id == user.id
            ).all():
                db.delete(t)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = data.password
        db.delete(token)
        db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
def login(
    data: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
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

        db.query(RefreshTokenModel).filter(
            RefreshTokenModel.user_id == user.id
        ).delete()

        token_data = {"user_id": user.id}
        access_token = jwt_manager.create_access_token(token_data)
        refresh_token = jwt_manager.create_refresh_token(token_data)

        new = RefreshTokenModel(user_id=user.id, token=refresh_token)
        db.add(new)
        db.commit()

        return UserLoginResponseSchema(
            token=access_token,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user = db.get(UserModel, payload["user_id"])

        token = db.query(RefreshTokenModel).filter_by(
            token=data.refresh_token
        ).first()

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        access_token = jwt_manager.create_access_token(payload)

        return {
            "access_token": access_token,
        }

    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
