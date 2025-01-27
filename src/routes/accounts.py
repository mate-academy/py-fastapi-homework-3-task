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
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
def register_user(user_data: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    existing_user = db.query(UserModel).filter_by(email=user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user_group = db.query(UserGroupModel).filter_by(name=UserGroupEnum.USER).first()
    new_user = UserModel(
        email=user_data.email,
        password=user_data.password,
        group=user_group
    )
    activation_token = ActivationTokenModel(user=new_user)

    try:
        db.add(new_user)
        db.add(activation_token)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return UserRegistrationResponseSchema(
        id=new_user.id,
        email=new_user.email
    )
