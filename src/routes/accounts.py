from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
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
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = user_group.scalar_one_or_none()

    hashed = hash_password(user.password)
    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed,
        group_id=cast(int, user_group.id),
        group=user_group,
    )

    try:
        db.add(db_user)
        await db.commit()
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    activation_token = ActivationTokenModel(
        user_id=cast(int, db_user.id),
        user=db_user,
    )
    try:
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        await db.delete(db_user)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    await db.refresh(db_user)
    return db_user