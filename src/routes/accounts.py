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

router = APIRouter()

@router.post("/auth/register")
async def register_user():
    pass


@router.post("/auth/activate")
async def activate_account():
    pass


@router.post("/auth/password-reset/request")
async def request_password_reset():
    pass


@router.post("/auth/password-reset/confirm")
async def confirm_password_reset():
    pass


@router.post("/auth/login")
async def login_user():
    pass


@router.post("/auth/refresh")
async def refresh_access_token():
    pass
