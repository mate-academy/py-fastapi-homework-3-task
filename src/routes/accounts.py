from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, InternalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config.dependencies import get_jwt_auth_manager, get_settings
from config.settings import BaseAppSettings
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from database.session_postgresql import get_postgresql_db
from database.validators.accounts import validate_password_strength, validate_email

from exceptions.security import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from security.passwords import hash_password, verify_password

from schemas.accounts import UserRegister, UserRegisterResponse, UserActivate, UserResetPassword, \
    UserResetPasswordComplete, LoginResponse, LoginRequest, RefreshAccessTokenResponse, RefreshAccessTokenRequest
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", status_code=201, response_model=UserRegisterResponse)
async def register_user(user: UserRegister, db: AsyncSession = Depends(get_postgresql_db)):
    result_users_emails = await db.execute(select(UserModel.email)).all()
    users_emails = await result_users_emails.scalars()
    if user.email in users_emails:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    try:
        hashed_password = hash_password(user.password)

        new_user = UserModel(
            email=user.email,
            hashed_password=hashed_password
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        token = ActivationTokenModel(
            user_id=user.id
        )
        db.add(token)
        user.activation_token = token

        result_groups = await db.execute(select(UserGroupModel).filter(UserGroupModel.name == "USER"))
        group_user = await result_groups.scalar_one_or_none()

        if not group_user:
            group = UserGroupModel(
                name=UserGroupEnum.USER
            )
            db.add(group)
            await db.commit()
            await db.refresh(group)

        new_user.group_id = group_user.id
        db.add(new_user)
        await db.commit()
        return {"message": "User registered successfully."}
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=200)
async def activate_account(db: AsyncSession = Depends(get_postgresql_db), user_data=UserActivate):
    result_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        result_activate_token = await db.execute(
            select(ActivationTokenModel).where(ActivationTokenModel.token == user_data.token))
        activate_token = await result_activate_token.scalar_one_or_none()

        if not activate_token or not activate_token == user_data.token:
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

        if activate_token.expires_at > datetime.now(timezone.utc) or user.activation_token != user_data.token:
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

        if user.is_active is True:
            raise HTTPException(status_code=400, detail="User account is already active")

        user.is_active = True
        await db.delete(activate_token)
        db.add(user)
        await db.commit()
        return {"message": "User account activated successfully."}

    except Exception as error:
        raise HTTPException(status_code=500, detail=f"An error occurred during account activation: {str(error)}")


@router.post("/password-reset/request/", status_code=200)
async def password_reset_request(user_data: UserResetPassword, db: AsyncSession = Depends(get_postgresql_db)):
    email = user_data.email
    if not "@" in email:
        raise HTTPException(status_code=400, detail="Invalid email.")

    result_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = await result_user.scalar_one_or_none()
    if user and user.is_active:
        try:
            reset_token = user.password_reset_token
            result_reset_token_model = await db.execute(
                select(PasswordResetTokenModel).where(PasswordResetTokenModel.token == reset_token))
            password_reset_obj = await result_reset_token_model.scalar_one_or_none()

            if not password_reset_obj:
                raise HTTPException(status_code=400, detail="User has not password reset token.")

            await db.delete(password_reset_obj)
            await db.delete(user.password_reset_token)
            new_reset_token_model = PasswordResetTokenModel(
                user_id=user.id
            )
            db.add(new_reset_token_model)
            await db.delete(user.password_reset_token)
            await db.commit()
            await db.refresh(new_reset_token_model)

            user.password_reset_token = new_reset_token_model

            db.add(user)
            await db.commit()

            return {"message": "If you are registered, you will receive an email with instructions."}

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An error occurred during password reset: {str(e)}")
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(db: AsyncSession = Depends(get_postgresql_db), user_data=UserResetPasswordComplete):
    result_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    result_token = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.token == user_data.token))
    token = await result_token.scalar_one_or_none()
    user = await result_user.scalar_one_or_none()
    password = validate_password_strength(user_data.password)

    if not token or token.expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()

        raise HTTPException(status_code=400, detail="Invalid email or token")

    if not "@" in user_data.email or not user.is_active or not user:
        raise HTTPException(status_code=400, detail="Invalid data or email")

    try:
        hashed_password = hash_password(user_data.password)
        user.hashed_password = hashed_password
        await db.delete(token)
        await db.commit()

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


def get_jwt_auth_manager_with_settings():
    settings = get_settings()
    return get_jwt_auth_manager(settings)


@router.post("/login/", response_model=LoginResponse)
async def login(
        user_data: LoginRequest,
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager_with_settings),
        db: AsyncSession = Depends(get_postgresql_db)):
    password = validate_password_strength(user_data.password)
    email = validate_email(user_email=str(user_data.email))

    result_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = await result_user.scalar_one_or_none()

    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    if user.hashed_password != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    try:
        new_refresh_token_generate = jwt_manager.create_refresh_token({"sub": str(user.id), "type": "refresh"})
        new_refresh_token = RefreshTokenModel.create(user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS,
                                                     token=new_refresh_token_generate)

        new_access_token_generate = jwt_manager.create_access_token({"sub": str(user.id), "type": "access"})
        db.add(new_refresh_token)
        await db.commit()

        return {"refresh_token": new_refresh_token_generate, "access_token": new_access_token_generate,
                "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=RefreshAccessTokenResponse)
async def refresh(user_data: RefreshAccessTokenRequest, db: AsyncSession = Depends(get_postgresql_db),
                  jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager_with_settings)):
    try:
        decode_token = jwt_manager.decode_refresh_token(user_data.refresh_token)
        token_expires_at = decode_token["exp"]
        token_user_id = int(decode_token["sub"])

        if not decode_token or datetime.fromtimestamp(token_expires_at, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Token has expired.")

        result_refresh_token = await db.execute(
            select(RefreshTokenModel).filter(RefreshTokenModel.token == user_data.refresh_token))
        refresh_token = result_refresh_token.scalar_one_or_none()

        if not refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        result_user = await db.execute(select(UserModel).where(UserModel.id == token_user_id))
        user = result_user.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        if user:
            new_access_token = jwt_manager.create_access_token({"sub": str(user.id), "type": "access"})
            if new_access_token:
                return {"access_token": new_access_token}
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"Invalid Data, error: {str(error)}")
