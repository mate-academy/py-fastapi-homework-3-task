from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, status, HTTPException
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
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.utils import generate_secure_token

router = APIRouter(tags=["accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = result.scalar_one()

    new_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )
    new_user.is_active = False
    new_user.created_at = datetime.now(timezone.utc)
    new_user.updated_at = datetime.now(timezone.utc)

    db.add(new_user)
    await db.flush()

    token = generate_secure_token()
    activation_token = ActivationTokenModel(
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        user_id=new_user.id,
    )
    db.add(activation_token)

    try:
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()
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

    result = await db.execute(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    token_record = result.scalar_one_or_none()

    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the user.",
        )

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        token = generate_secure_token()
        reset_token = PasswordResetTokenModel(
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user_id=user.id,
        )
        db.add(reset_token)

        try:
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            return {"message": "If you are registered, you will receive an email with instructions."}

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == payload.email))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        result = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        token_record = result.scalar_one_or_none()

        if not token_record or token_record.token != payload.token:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user._hashed_password = hash_password(payload.password)

        await db.delete(token_record)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=TokenResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    credentials: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(select(UserModel).where(UserModel.email == credentials.email))
    user = result.scalars().first()
    if not user or not user.verify_password(credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return TokenResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
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
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token.")

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
