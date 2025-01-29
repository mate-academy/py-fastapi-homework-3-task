from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database.models.accounts import TokenBaseModel
from schemas import UserLoginRequestSchema, TokenRefreshRequestSchema
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    MessageResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token

router = APIRouter()


def get_user_by_email(db: Session, email: str):
    return db.query(UserModel).filter(UserModel.email == email).first()


def delete_token(token: TokenBaseModel, user: UserModel, db: Session):
    db.delete(token)
    db.commit()
    db.refresh(user)


@router.post(
    "/register", response_model=UserRegistrationResponseSchema, status_code=201
)
def create_user(user: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {existing_user.email} already exists.",
        )

    try:
        hashed_password = hash_password(user.password)
        default_group = (
            db.query(UserGroupModel)
            .filter(UserGroupModel.name == UserGroupEnum.USER)
            .first()
        )

        new_user = UserModel(
            email=user.email,
            _hashed_password=hashed_password,
            group_id=default_group.id,
        )

        activation_token = ActivationTokenModel(
            token=generate_secure_token(), user=new_user
        )
        new_user.activation_token = activation_token

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )
    return new_user


@router.post("/activate", response_model=MessageResponseSchema)
def activate_account(data: UserActivationRequestSchema, db: Session = Depends(get_db)):
    activation_token = (
        db.query(ActivationTokenModel)
        .join(UserModel)
        .filter(ActivationTokenModel.token == data.token, UserModel.email == data.email)
        .first()
    )
    now_ = datetime.now(timezone.utc).replace(tzinfo=None)

    if not activation_token or activation_token.expires_at < now_:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if activation_token.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    try:
        user = activation_token.user
        user.is_active = True

        delete_token(activation_token, user, db)

    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Something went wrong.")

    message = "User account activated successfully."
    return MessageResponseSchema(message=message)


@router.post("/password-reset/request", response_model=MessageResponseSchema)
def create_password_reset_token(
    user: PasswordResetRequestSchema, db: Session = Depends(get_db)
):
    existing_user = get_user_by_email(db, user.email)
    if existing_user and existing_user.is_active:
        password_reset_token = existing_user.password_reset_token
        if password_reset_token:
            delete_token(password_reset_token, existing_user, db)

        new_password_reset_token = PasswordResetTokenModel(
            token=generate_secure_token(), user=existing_user
        )
        db.add(new_password_reset_token)

        existing_user.password_reset_token = new_password_reset_token
        db.commit()
        db.refresh(existing_user)
    message = "If you are registered, you will receive an email with instructions."
    return MessageResponseSchema(message=message)


@router.post("/reset-password/complete", response_model=MessageResponseSchema)
def reset_password(
    data: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)
):
    password_reset_token = (
        db.query(PasswordResetTokenModel)
        .join(UserModel)
        .filter(
            PasswordResetTokenModel.token == data.token,
        )
        .first()
    )
    now_ = datetime.now(timezone.utc).replace(tzinfo=None)
    user = get_user_by_email(db, data.email)
    if not password_reset_token or password_reset_token.expires_at < now_:
        if user:
            tokens = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).all()
            for token in tokens:
                db.delete(token)
            db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if not user or not user.is_active:
        tokens = db.query(PasswordResetTokenModel).filter_by(user_id=user.id).all()
        for token in tokens:
            db.delete(token)
        db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        hashed_new_password = hash_password(data.password)
        user._hashed_password = hashed_new_password

        delete_token(password_reset_token, user, db)
        db.commit()
        db.refresh(user)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    message = "Password reset successfully."
    return MessageResponseSchema(message=message)


@router.post("/login", response_model=UserLoginResponseSchema, status_code=201)
def login(
    data: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    existing_user = get_user_by_email(db, data.email)
    if not existing_user or not verify_password(
        data.password, existing_user._hashed_password
    ):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not existing_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(
            data={"sub": existing_user.email, "user_id": existing_user.id}
        )
        refresh_token = jwt_manager.create_refresh_token(
            data={"sub": existing_user.email, "user_id": existing_user.id}
        )
        refresh_token_model = RefreshTokenModel.create(
            user_id=existing_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_model)
        db.commit()
        db.refresh(existing_user)

    except Exception:
        db.rollback()
        raise HTTPException(
            500, detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh", response_model=TokenRefreshResponseSchema)
def refresh_access_token(
    refresh_token: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_id = decoded_token.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    refresh_token_str = refresh_token.refresh_token
    stored_refresh_token = (
        db.query(RefreshTokenModel).filter_by(token=refresh_token_str).first()
    )

    if not stored_refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = db.query(UserModel).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        new_access_token = jwt_manager.create_access_token(
            data={"sub": user.email, "user_id": user.id}
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to generate access token.")

    return TokenRefreshResponseSchema(access_token=new_access_token)
