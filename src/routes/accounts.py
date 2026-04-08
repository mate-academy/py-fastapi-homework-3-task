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


from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
)

router = APIRouter()


async def get_one_user(
    db: AsyncSession,
    model: type,
    filters: list[ColumnElement[bool]],
    options: list | None = None,
):
    query = select(model)
    if options:
        query = query.options(*options)
    if filters:
        query = query.where(*filters)

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
    existing_user = await get_one_user(
        db, model=UserModel, filters=[UserModel.email == user_data.email]
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = await get_one_user(
            db, UserGroupModel, filters=[UserGroupModel.name == UserGroupEnum.USER]
        )

        if not group:
            raise HTTPException(
                status_code=500, detail="Default user group not configured."
            )

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
            detail="An error occurred during user creation.",
        )


@router.post("/activate", response_model=MessageResponseSchema)
async def activate_user(
    user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await get_one_user(
        db,
        model=UserModel,
        options=[joinedload(UserModel.activation_token)],
        filters=[UserModel.email == user_data.email],
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_record = user.activation_token
    is_token_invalid = (
        not token_record
        or token_record.token != user_data.token
        or datetime.now(timezone.utc) > token_record.expires_at
    )

    if is_token_invalid:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=400, detail="An error occurred during user activation."
        )

    return {"message": "User account activated successfully."}
