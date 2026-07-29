from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
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
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from src.schemas import accounts


router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == email)
        .options(joinedload(UserModel.group))
    )
    return result.unique().scalar_one_or_none()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=accounts.UserRegistrationResponseSchema
)
async def register_user(
    data: accounts.UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserModel:
    user = await get_user_by_email(db, data.email)

    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A user with this email {user.email}"
                " already exists."
            )
        )

    try:
        group_result = await db.execute(
            select(UserGroupModel)
            .where(UserGroupModel.name == UserGroupEnum.USER.value())
        )
        group = group_result.scalar_one()
        user = UserModel.create(
            email=data.email,
            raw_password=data.password,
            group_id=group.id
        )
        activation_token = ActivationTokenModel(user_id=user.id)

        db.add(activation_token)
        await db.commit()

        return user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
