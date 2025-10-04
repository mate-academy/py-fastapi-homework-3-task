from datetime import datetime, timezone, timedelta
from fastapi import Request

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

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema
)

from src.schemas.accounts import TokenRefreshResponseSchema, TokenRefreshRequestSchema

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register(
    data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {data.email} already exists."
        )

    try:
        new_user = UserModel.create(
            email=data.email,
            raw_password=data.password,
            group_id=1
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(activation_token)

        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):

    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    query = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    token_expiration = token_record.expires_at
    if token_expiration.tzinfo is None:
        token_expiration = token_expiration.replace(tzinfo=timezone.utc)

    if token_expiration < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()
        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during activation."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel)
                         .where(PasswordResetTokenModel.user_id == user.id))
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()
    return MessageResponseSchema()


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    query = (select(PasswordResetTokenModel)
             .where(PasswordResetTokenModel.user_id == user.id))
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    if not token_record or token_record.token != data.token:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        refresh_token_create = jwt_manager.create_refresh_token(
            {"user_id": user.id},
            timedelta(days=settings.LOGIN_TIME_DAYS)
        )

        access_token_create = jwt_manager.create_access_token(
            {"user_id": user.id}
        )

        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_create
        )

        db.add(refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token_create,
            refresh_token=refresh_token_create,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200
)
async def refresh(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    refresh_token = data.refresh_token
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail="No refresh token provided"
        )

    try:
        payload = jwt_manager.decode_refresh_token(refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    query = (select(RefreshTokenModel)
             .where(RefreshTokenModel.token == refresh_token))
    result = await db.execute(query)
    refresh_token_record = result.scalar_one_or_none()

    if not refresh_token_record:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user_id = payload.get("user_id")
    query = select(UserModel).where(UserModel.id == int(user_id))
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
