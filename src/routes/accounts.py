from datetime import datetime, timezone

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
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


@router.post(
    "/register",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED)
def register(
        user_data: UserRegistrationRequestSchema,
        db: Session = Depends(get_db)
):
    user_exist = db.query(UserModel).filter_by(email=user_data.email).first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()
    try:
        user = UserModel(
            email=user_data.email,
            password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        db.commit()
        db.refresh(user)

        return user
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
def activate(
        user_data: UserActivationRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()
    activation_token = db.query(ActivationTokenModel).filter_by(user_id=user.id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No user with email {user_data.email} was found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user_data.token != activation_token.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if activation_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True
        db.delete(activation_token)
        db.commit()

        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
def request_password_reset(
        user_data: PasswordResetRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user or user.is_active is False:
        return {"message": "If you are registered, you will receive an email with instructions."}

    try:
        existing_reset_passwords = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).all()
        if existing_reset_passwords:
            for reset_password in existing_reset_passwords:
                db.delete(reset_password)

        new_reset_password = PasswordResetTokenModel(user_id=user.id)
        db.add(new_reset_password)
        db.commit()

        return {"message": "If you are registered, you will receive an email with instructions."}
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during the password reset.",
        )


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
def complete_password_reset(
        user_data: PasswordResetCompleteRequestSchema,
        db: Session = Depends(get_db),
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user or user.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_password = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).first()

    if not reset_password or user_data.token != reset_password.token:
        if reset_password:
            db.delete(reset_password)
            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

    if reset_password.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        if reset_password:
            db.delete(reset_password)
            db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

    try:
        user.password = user_data.password
        db.delete(reset_password)
        db.commit()

        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def login(
        user_data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if user.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    if not user.verify_password(raw_password=user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    try:
        access_token = jwt_auth_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_auth_manager.create_refresh_token({"user_id": user.id})
        db_refresh_token = RefreshTokenModel(user_id=user.id, token=refresh_token)
        db.add(db_refresh_token)
        db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
def refresh(
        user_data: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_auth_manager.decode_refresh_token(user_data.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    token_exist = db.query(RefreshTokenModel).filter_by(token=user_data.refresh_token).first()

    if not token_exist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = db.query(UserModel).filter_by(id=user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_auth_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
