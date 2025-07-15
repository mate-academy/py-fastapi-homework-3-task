from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete, update
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

from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)

from crud.accounts import create_user, get_user_by_email
from security.utils import generate_secure_token
from security.passwords import hash_password, verify_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user_data.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")
    try:
        return await create_user(
            db=db,
            user=user_data,
        )
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, user_data.email)

    if not user:
        raise HTTPException(status_code=404, detail=f"User with email {user_data.email} does not exist.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == user_data.token,
            ActivationTokenModel.user_id == user.id
        )
    )
    token = result.scalar_one_or_none()

    if not token or token.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, user_data.email)

    if user and user.is_active:
        result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        existing_token = result.scalar_one_or_none()

        if existing_token:
            await db.delete(existing_token)
            await db.flush()

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(new_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        user = await get_user_by_email(db, data.email)

        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        result_token = await db.execute(
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
            .order_by(PasswordResetTokenModel.expires_at.desc())
            .limit(1)
        )
        token_record = result_token.scalar_one_or_none()

        is_invalid = (
            not token_record
            or token_record.token != data.token
            or token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        )

        if is_invalid:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = data.password

        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException as he:
        await db.rollback()
        raise he
    except Exception as e:
        await db.rollback()
        print(f"UNEXPECTED ERROR in reset_password_complete: {e}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user = await get_user_by_email(db, data.email)

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_entry = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_entry)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload.")

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalar_one_or_none()

    if not refresh_token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {"access_token": access_token}
