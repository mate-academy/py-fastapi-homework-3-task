from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from fastapi.security import OAuth2PasswordBearer

from config import get_jwt_auth_manager
from crud.user import get_user_by_email, create_user, activate_user
from database import (
    get_db,
    UserModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from schemas.accounts import PasswordResetCompleteSchema

from security.token_manager import JWTAuthManager

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", status_code=status.HTTP_201_CREATED, response_model=UserRegistrationResponseSchema)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        db_user = await get_user_by_email(db, user.email)
        if db_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {db_user.email} already exists."
            )
        return await create_user(db, user)
    except HTTPException:
        raise
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        await activate_user(db, data.email, data.token)
        return {"message": "User account activated successfully."}
    except BaseSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during account activation."
        )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_password_request(
    data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == data.email)
        )
        user = result.unique().scalar_one_or_none()

        message = "If you are registered, you will receive an email with instructions."

        if not user or not user.is_active:
            return {"message": message}

        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.flush()

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()

        return {"message": message}

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password_complete(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == data.email)
        )
        user = result.unique().scalar_one_or_none()

        if not user or not user.password_reset_token:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_record = user.password_reset_token
        token_value = data.token.strip()

        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if token_record.token != token_value or expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = data.password
        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == data.email))
        user = result.scalar_one_or_none()

        if not user or not user.verify_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=7,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    token_record = result.scalars().first()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {"access_token": access_token, "token_type": "bearer"}
