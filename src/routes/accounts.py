from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserActivationRequestSchema
from schemas.accounts import (
    UserRegistrationResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
):
    query_user = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    existing_user = query_user.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )
    query_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = query_group.scalar_one_or_none()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    try:
        hashed_password = hash_password(user.password)
        new_user = UserModel(
            email=user.email,
            _hashed_password=hashed_password,
            is_active=False,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        token = ActivationTokenModel(
            user_id=new_user.id,
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=settings.ACTIVATION_TOKEN_EXPIRE_DAYS),
        )
        db.add(token)
        await db.commit()
        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(
    data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    query_user = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = query_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )
    query_token = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token,
        )
    )
    token_record = query_token.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()

        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
):
    success_response = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    query_user = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = query_user.scalar_one_or_none()
    if not user or not user.is_active:
        return success_response
    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        expire_days = getattr(settings, "PASSWORD_RESET_TOKEN_EXPIRE_DAYS", 7)
        new_token = PasswordResetTokenModel(
            user_id=cast(int, user.id),
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=expire_days),
        )
        db.add(new_token)
        await db.commit()
        return success_response
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    querty_user = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = querty_user.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    query_token = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    token_record = query_token.scalar_one_or_none()
    if not token_record or token_record.token != data.token:
        if token_record:
            try:
                await db.delete(token_record)
                await db.commit()
            except SQLAlchemyError:
                await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        try:
            await db.delete(token_record)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    try:
        user._hashed_password = hash_password(data.password)
        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    query_user = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = query_user.scalar_one_or_none()

    if not user or not verify_password(data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id, token=refresh_token, days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_token_record)

        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    query_token = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    token_record = query_token.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    query_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = query_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return {"access_token": new_access_token}
