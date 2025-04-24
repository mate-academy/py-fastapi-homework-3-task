from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.responses import JSONResponse

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud import get_user_by_email, create_user
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
from src.schemas.accounts import UserCreate, Token
from src.security.interfaces import JWTAuthManagerInterface
from src.security.passwords import verify_password, hash_password
from src.security.token_manager import JWTAuthManager
from dotenv import load_dotenv
import os


load_dotenv()

router = APIRouter()

secret_key_access = os.getenv("SECRET_KEY_ACCESS")
secret_key_refresh = os.getenv("SECRET_KEY_REFRESH")
algorithm = os.getenv("JWT_SIGNING_ALGORITHM")


@router.post("/activate", response_model=JSONResponse,)
async def activate(user: UserCreate,
                   jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                   db: AsyncSession = Depends(get_db)):

    token_expires = timedelta(minutes=15)
    activation_token = jwt_manager.create_access_token(
        data={"sub": user.email},
        expires_delta=token_expires
    )

    try:
        user.is_active = True
        return JSONResponse("User account activated successfully.")
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/register", response_model=UserModel)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    try:
        return await create_user(db, user)
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/password-reset/request/", response_model=str)
async def reset_password_request(email: str,
                                 password: str,
                                 db: AsyncSession = Depends(get_db),
                                 jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),):
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token_expires = timedelta(minutes=15)
    activation_token = jwt_manager.create_access_token(
        data={"sub": email},
        expires_delta=token_expires
    )
    new_token = PasswordResetTokenModel()
    new_token.token = activation_token
    new_token.expires_at = token_expires
    db_user.password_reset_token = new_token
    try:
        return "If you are registered, you will receive an email with instructions."
    except Exception:
        raise HTTPException(status_code=500)


@router.post("/password-reset/complete/", response_model=str)
async def reset_password_complete(email: str,
                                token: str,
                                password: str,
                                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                                db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    jwt_manager.verify_access_token_or_raise(token)
    db_user.password = password

    try:
        return "The password is successfuly reset."
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login", response_model=Token)
async def login(email: str,
                password: str,
                db: AsyncSession = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token_expires = timedelta(minutes=15)
    access_token = jwt_manager.create_access_token(
        data={"sub": db_user.email}, expires_delta=access_token_expires
    )
    token_expires = timedelta(minutes=15)
    refresh_token= jwt_manager.create_refresh_token(data={"sub": email},
        expires_delta=token_expires)
    try:
        return  Token(access_token=access_token, refresh_token=refresh_token, token_type="bearer")
    except:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/api/v1/accounts/refresh/", response_model=ActivationTokenModel)
async def access_token_refresh(email: str,
                refresh_token: str,
                password: str,
                db: AsyncSession = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="User not found.")

    jwt_manager.decode_refresh_token(refresh_token)
    jwt_manager.verify_refresh_token_or_raise((refresh_token))

    token_expires = timedelta(minutes=15)
    access_token = jwt_manager.create_access_token(data={"sub": email},
        expires_delta=token_expires
    )
    try:
        return access_token
    except:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")