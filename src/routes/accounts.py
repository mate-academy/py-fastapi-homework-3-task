from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema
from schemas.accounts import UserResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.utils import generate_secure_token

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.post(
    "/register", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    query_user = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    existing_user = query_user.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with email {user.email} already exists.",
        )
    query_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = query_group.scalar_one_or_none()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found. Please contact administration.",
        )
    try:
        hashed_password = hash_password(user.password)
        new_user = UserModel(
            email=user.email,
            hashed_password=hashed_password,
            is_active=False,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        settings = get_settings()
        token = ActivationTokenModel(
            user_id=new_user.id,
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.ACTIVATION_TOKEN_EXPIRE_DAYS),
        )
        db.add(token)
        await db.commit()
        return UserResponseSchema(id=new_user.id, email=new_user.email)
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating your account. Please try again later.",
        )
