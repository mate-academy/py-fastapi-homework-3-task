from datetime import datetime, timezone
from typing import cast

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
from exceptions import BaseSecurityError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface

from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
def register(register_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    user_exist = db.query(UserModel).filter_by(email=register_data.email).first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {register_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()

    try:
        user = UserModel.create(
            email=register_data.email,
            raw_password=register_data.password,
            group_id=user_group.id
        )

        db.add(user)
        db.flush()
        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        db.commit()
        db.refresh(user)
        db.refresh(activation_token)

        return user

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
def activate(
        activate_data: UserActivationRequestSchema,
        db: Session = Depends(get_db),
):
    token_record = (
        db.query(ActivationTokenModel)
        .join(UserModel)
        .filter(
            UserModel.email == activate_data.email,
            ActivationTokenModel.token == activate_data.token,
        )
        .first()
    )

    if not token_record or cast(datetime, token_record.expires_at).replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        if token_record:
            db.delete(token_record)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    db.delete(token_record)
    db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
def request_password_reset_token(
    data: PasswordResetRequestSchema,
    db: Session = Depends(get_db),
) -> MessageResponseSchema:
    db_user = db.query(UserModel).filter_by(email=data.email).first()

    if not db_user or not db_user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    db.query(PasswordResetTokenModel).filter_by(user_id=db_user.id).delete()

    reset_token = PasswordResetTokenModel(user_id=cast(int, db_user.id))
    db.add(reset_token)
    db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
def reset_password(
    password_data: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db),
) -> MessageResponseSchema:
    user = db.query(UserModel).filter_by(email=password_data.email).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    token_record = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).first()

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if (
            not token_record
            or token_record.token != password_data.token
            or expires_at < datetime.now(timezone.utc)
    ):
        if token_record:
            db.delete(token_record)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user.password = password_data.password
        db.delete(token_record)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", status_code=status.HTTP_201_CREATED)
def login(
        user_data: UserLoginRequestSchema,
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter_by(email=user_data.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    user_password_verify = user.verify_password(raw_password=user_data.password)

    if user_password_verify:
        access_token = jwt_auth_manager.create_access_token(
            {"user_id": user.id}
        )

        refresh_token = jwt_auth_manager.create_refresh_token(
            {"user_id": user.id}
        )

        refresh_token_model = RefreshTokenModel(
            user=user,
            token=refresh_token,
        )

        try:
            db.add(refresh_token_model)
            db.commit()
            db.refresh(refresh_token_model)
        except SQLAlchemyError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request."
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    refresh_token_record = (
        db.query(RefreshTokenModel).filter_by(token=token_data.refresh_token).first()
    )
    if not refresh_token_record:
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

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
