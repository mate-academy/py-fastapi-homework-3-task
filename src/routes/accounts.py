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
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register")
async def register(email: str,
                   password: str,
                   db: AsyncSession = Depends(get_db),
                   jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    hashed_password = hash_password(password)
    created_at = datetime.now(timezone.utc)
    user_group_smt = select(UserGroupModel).filter(UserGroupModel.id == UserGroupEnum.USER)
    user_group = await db.execute(user_group_smt)
    user_group = user_group.first()
    activation_token = jwt_auth_manager.create_access_token()
    user = UserModel(
        email=email,
        _hashed_password=hashed_password,
        created_at=created_at,
        updated_at=created_at,
        group=user_group,
        group_id=user_group.id,
        activation_token=activation_token)
    await db.add(user)
    await db.commit()
