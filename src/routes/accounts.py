from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from exceptions import InvalidTokenError, TokenExpiredError

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel, crud
)
from exceptions import BaseSecurityError, security
from schemas.accounts import (
    ActivateAccountRequest,
    TokenRefreshRequestSchema,
    PasswordResetRequestSchema,
    UserRegistrationRequestSchema,
    UserLoginRequestSchema,
    PasswordResetCompleteRequest,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password
from security import token_manager

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    try:
        return await crud.create_user(db, user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(detail="An error occurred during user creation.", status_code=500)


@router.post("/login/", status_code=status.HTTP_200_OK)
async def login(
        user: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await crud.get_user_by_email(db, email=user.email)
    if db_user is None or not db_user.verify_password(user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_auth_manager.create_access_token(data={"user_id": db_user.id})

    refresh_token = jwt_auth_manager.create_refresh_token(data={"user_id": db_user.id})

    try:
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(db_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(payload: ActivateAccountRequest, db: AsyncSession = Depends(get_db)):
    token = await crud.activate_user(db, payload=payload)

    if token is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user = token.user
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    user.is_active = True
    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.id == token.id))
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password_request(payload: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    response = {
        "message": "If you are registered, you will receive an email with instructions."
    }
    db_user = await crud.get_user_by_email(db, payload.email)
    if db_user is None or not db_user.is_active:
        return response

    try:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))
        new_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Internal Server Error")
    return response


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(payload: PasswordResetCompleteRequest, db: AsyncSession = Depends(get_db)):
    db_user = await crud.get_user_by_email(db, email=payload.email)

    if db_user is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )
    reset_token = result.scalar_one_or_none()

    if reset_token is None or reset_token.token != payload.token:
        if reset_token is not None:
            await db.delete(reset_token)
            await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if not db_user.is_active or expires_at < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user.password = payload.password

        await db.delete(reset_token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        token_data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(
            status_code=400,
            detail="Invalid token.",
        )

    try:
        user_id = token_data["user_id"]
    except (KeyError, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    refresh_token = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    )
    refresh_token_result = refresh_token.scalar_one_or_none()

    if refresh_token_result is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(
        select(UserModel).where(UserModel.id == int(user_id))
    )
    db_user = result.scalar_one_or_none()

    if db_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }
