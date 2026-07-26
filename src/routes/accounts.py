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
from database.crud.users import UserAlreadyExistsError
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/")
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
