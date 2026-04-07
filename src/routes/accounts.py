from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, ColumnElement
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
from security.interfaces import JWTAuthManagerInterface


from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema

router = APIRouter()


async def get_one_user(
    db: AsyncSession,
    model: type,
    filters: list[ColumnElement[bool]],
    options: list,
):
    query = select(model)

    if options:
        for o in options:
            query = query.options(o)
    if filters:
        for f in filters:
            query = query.filter(f)
    result = await db.execute(query)
    return result.scalar_one_or_none()


@router.post(
    "/register",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        existing_user = await get_one_user(
            db, model=UserModel, filters=[UserModel.email == user_data.email]
        )

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email {user_data.email} already registered.",
            )

        group = await get_one_user(
            db, UserGroupModel, filters=[UserGroupModel.name == UserGroupEnum.USER]
        )

        if not group:
            raise HTTPException(status_code=500, detail="Default group not found.")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )

        ActivationTokenModel(user=new_user)

        db.add(new_user)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal Server Error",
        )
