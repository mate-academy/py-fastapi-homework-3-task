from fastapi import HTTPException, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from database.models.accounts import (
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationResponseSchema,
    TokenResetSchema,
)

from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from config import get_jwt_auth_manager, get_settings, BaseAppSettings


def get_user_by_email(db: Session, email: str):
    return db.query(UserModel).filter(UserModel.email == email).first()


def get_user_by_id(db: Session, user_id: int):
    return db.query(UserModel).filter(UserModel.id == user_id).first()


def create_user(db: Session, user: UserModel):
    try:
        new_user = UserModel(
            email=user.email, password=user.password, group_id=user.group_id
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return UserRegistrationResponseSchema.model_validate(new_user)
    except IntegrityError as err:
        db.rollback()
        raise HTTPException(
            status_code=500, detail=str(err)
        )


def create_activation_token(db: Session, user: UserModel):
    try:
        new_user = create_user(db, user)
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        db.commit()
        db.refresh(activation_token)
        return UserRegistrationResponseSchema.model_validate(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


def create_reset_token(db: Session, user: UserModel):
    try:
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        db.commit()
        db.refresh(reset_token)
        return TokenResetSchema.model_validate(reset_token)
    except Exception as err:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred during user creation. {str(err)}",
        )


def get_refresh_token(
        db_user: UserModel, db: Session
):
    db_refresh_token = (
        db.query(RefreshTokenModel)
        .filter(RefreshTokenModel.user == db_user)
        .first()
    )

    return db_refresh_token


def create_and_store_refresh_token(
        db_user: UserModel,
        db: Session,
        jwt_manager: JWTAuthManagerInterface,
        settings: BaseAppSettings
):
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": db_user.id})
    db_refresh_token = RefreshTokenModel.create(
        user_id=db_user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )
    db.add(db_refresh_token)
    db.commit()
    db.refresh(db_refresh_token)

    return db_refresh_token
