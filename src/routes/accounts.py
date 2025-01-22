from passlib.context import CryptContext
from datetime import datetime, timezone
from typing import cast

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

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_data: UserRegistrationRequestSchema,
    db: Session = Depends(get_db)
):
    user_existense = db.query(UserModel).filter_by(email=user_data.email).first()

    if user_existense:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

    if not user_group:
        try:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            db.commit()
            db.refresh(user_group)
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while creating the user group."
            )

    hashed_password = pwd_context.hash(user_data.password)

    try:
        new_user = UserModel.create(
            email=str(user_data.email),
            hashed_password=hashed_password,
            group_id=user_group.id,
        )
        db.add(new_user)
        db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        db.commit()
        db.refresh(new_user)
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    else:
        return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
)
def activate_user_account(
        activation_data: UserActivationRequestSchema,
        db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter_by(email=activation_data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email not found."
        )

    activation_token = db.query(ActivationTokenModel).filter_by(user_id=user.id).first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if activation_token.expiration_date < datetime.now(timezone.utc):
        db.delete(activation_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    db.commit()

    db.delete(activation_token)
    db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
)
def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter_by(email=reset_data.email).first()

    if user:
        db.query(PasswordResetTokenModel).filter_by(user_id=user.id).delete()
        db.commit()

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
)
def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter_by(email=reset_data.email).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token = db.query(PasswordResetTokenModel).filter_by(user_id=user.id, token=reset_data.token).first()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if reset_token.expiration_date < datetime.now(timezone.utc):
        db.delete(reset_token)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token."
        )

    hashed_password = pwd_context.hash(reset_data.password)
    try:
        user.hashed_password = hashed_password
        db.commit()

        db.delete(reset_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


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

    if not user or not pwd_context.verify(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_auth_manager.create_access_token(data={"sub": user.email})
    refresh_token = jwt_auth_manager.create_refresh_token(data={"sub": user.email})

    try:
        db.add(RefreshTokenModel(user_id=user.id, token=refresh_token))
        db.commit()
    except SQLAlchemyError:
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


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
def refresh_token(
    data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    refresh_token = data.refresh_token

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required."
        )

    try:
        payload = jwt_auth_manager.decode_refresh_token(refresh_token)
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    token_record = db.query(RefreshTokenModel).filter_by(token=refresh_token).first()
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = db.query(UserModel).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_auth_manager.create_access_token(data={"sub": user.email})

    return {"access_token": access_token}
