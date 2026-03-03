from datetime import datetime

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
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
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.utils import generate_secure_token


router = APIRouter()


def _is_expired(expires_at: datetime) -> bool:
    current_time = datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now()
    return expires_at < current_time


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        existing_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        if existing_user.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        user_group_instance = user_group.scalars().first()
        if not user_group_instance:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation."
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group_instance.id
        )
        db.add(new_user)

        activation_token = ActivationTokenModel(
            token=generate_secure_token(),
            user=new_user
        )
        db.add(activation_token)

        await db.commit()
        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid activation data."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if not user.activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if (
        user.activation_token.token != activation_data.token
        or _is_expired(user.activation_token.expires_at)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema
)
async def request_password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == reset_request.email))
    user = result.scalars().first()

    if user and user.is_active:
        reset_token = PasswordResetTokenModel(
            token=generate_secure_token(),
            user=user
        )
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == reset_data.email)
        )
        user = result.scalars().first()

        if not user or not user.password_reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        if (
            user.password_reset_token.token != reset_data.token
            or _is_expired(user.password_reset_token.expires_at)
        ):
            await db.delete(user.password_reset_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = reset_data.password
        await db.delete(user.password_reset_token)
        await db.commit()

        return MessageResponseSchema(
            message="Password reset successfully."
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == login_data.email))
        user = result.scalars().first()

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        access_token = jwt_auth_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_auth_manager.create_refresh_token({"user_id": user.id})

        refresh_tokens = await db.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id)
        )
        for token in refresh_tokens.scalars().all():
            await db.delete(token)

        refresh_token_model = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=jwt_auth_manager._REFRESH_KEY_TIMEDELTA_MINUTES // (60 * 24),
            token=refresh_token,
        )
        db.add(refresh_token_model)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def refresh_tokens(
    refresh_request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_auth_manager.decode_refresh_token(refresh_request.refresh_token)
        user_id = payload.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token."
            )

        refresh_tokens = await db.execute(
            select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_request.refresh_token)
        )
        valid_token = refresh_tokens.scalars().first()

        if not valid_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        result = await db.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalars().first()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        access_token = jwt_auth_manager.create_access_token({"user_id": user.id})

        return TokenRefreshResponseSchema(
            access_token=access_token
        )
    except BaseSecurityError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        )
