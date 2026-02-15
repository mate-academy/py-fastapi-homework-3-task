from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, InternalError
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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLogin,
    UserRefreshToken,
    UserAccessToken,
    UserLoginResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(user_to_add: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result_user = await db.execute(select(UserModel).where(UserModel.email == user_to_add.email))
    db_user = result_user.scalar_one_or_none()
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")

    result_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = result_group.scalar_one_or_none()
    if not user_group:
        raise HTTPException(status_code=500, detail="Default user group not found.")

    try:
        new_user = UserModel.create(
            email=user_to_add.email,
            raw_password=user_to_add.password,
            group_id=user_group.id,
        )
        activation_token = ActivationTokenModel(user=new_user)
        new_user.activation_token = activation_token

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        return new_user

    except ValueError as e:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(e))

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result_user.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result_token = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == data.token)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    db_token = result_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token_expires_at = db_token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    try:
        db_user.is_active = True
        await db.delete(db_token)
        await db.commit()
        await db.refresh(db_user)
        return {"message": "User account activated successfully."}

    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred during user activation.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
        db_user = result_user.scalar_one_or_none()

        if db_user and db_user.is_active:
            await db.execute(delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            ))
            new_reset_token = PasswordResetTokenModel(
                user_id=db_user.id
            )
            db.add(new_reset_token)
            await db.commit()
            await db.refresh(new_reset_token)

    except Exception:
        await db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result_user.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result_token = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
    )
    db_token = result_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_expires_at = db_token.expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)

    if db_token.token != data.token or token_expires_at < datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    db_user.password = hash_password(data.password)
    await db.delete(db_token)
    await db.commit()
    await db.refresh(db_user)

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        data: UserLogin,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    try:
        result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
        db_user = result_user.scalar_one_or_none()

        if not db_user or not db_user.verify_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if not db_user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token(
            data={"user_id": db_user.id}
        )
        refresh_token_str = jwt_manager.create_refresh_token(
            {"user_id": db_user.id}
        )
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str,
        )
        db.add(refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer"
        }

    except HTTPException:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=UserAccessToken, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        refresh_token: UserRefreshToken,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        validated_refresh_token = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
        user_id = int(validated_refresh_token["user_id"])

    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")

    try:
        result_token = await db.execute(select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token.refresh_token
        ))
        db_token = result_token.scalar_one_or_none()

        if not db_token:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        result_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
        user = result_user.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        access_token = jwt_manager.create_access_token(
            data={"user_id": user.id}
        )

        return {"access_token": access_token}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")
