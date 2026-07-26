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
from database.crud import users as users_crud
from database.crud.exceptions import UserAlreadyExistsError, UserNotExistsError, UserException
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, UserActivationRequestSchema, \
    MessageResponseSchema, PasswordResetRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    try:
        new_user = await users_crud.create_user(session=db, user_data=user_data)
    except UserAlreadyExistsError:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")
    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post("/activate/")
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    try:
        await users_crud.activate_user(session=db, email=data.email, token=data.token)
    except UserException as e:
        raise HTTPException(status_code=409, detail=f"{e}")
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/")
async def reset_password_request(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    await users_crud.create_password_reset_token(session=db, email=data.email)
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")
