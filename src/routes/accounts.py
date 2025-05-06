from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    async with db as session:
        user_exists_result = await session.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        user_exists = user_exists_result.scalar_one_or_none()
        if user_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        try:
            group_result = await session.execute(
                select(UserGroupModel).where(
                    UserGroupModel.name == UserGroupEnum.USER
                )
            )
            # if there is no such group, error 500 will occur, no need to check, this is the logic of the task
            group = group_result.scalar_one_or_none()
            # use UserModel method to create new user with hashed password
            new_user = UserModel.create(
                email=user_data.email,
                raw_password=user_data.password,
                group_id=group.id,
            )
            session.add(new_user)
            await session.flush()
            await session.refresh(new_user)
            activation_token = ActivationTokenModel(user=new_user)
            session.add(activation_token)
            await session.commit()
            return new_user
        except Exception:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    async with db as session:
        user_result = await session.execute(
            select(UserModel)
            .options(joinedload(UserModel.activation_token))
            .where(UserModel.email == user_data.email)
        )
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"A user with this email {user_data.email} does not exist.",
            )

        activation_token = user.activation_token

        if user.is_active:
            if activation_token:
                await session.delete(activation_token)
                await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        if (
            not user.activation_token
            or activation_token.token != user_data.token
            or activation_token.expires_at.replace(tzinfo=timezone.utc)
            < datetime.now(timezone.utc)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True
        await session.delete(activation_token)
        await session.commit()
        await session.refresh(user)
        return MessageResponseSchema(
            message="User account activated successfully."
        )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_token_request(
    request_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    async with db as session:
        user_result = await session.execute(
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == request_data.email)
        )
        user = user_result.scalar_one_or_none()

        if user and user.is_active:
            reset_token_db = user.password_reset_token
            if reset_token_db:
                await session.delete(reset_token_db)
                await session.commit()

            try:
                reset_token = PasswordResetTokenModel(user=user)
                session.add(reset_token)
                await session.commit()
                await session.refresh(reset_token)
            except Exception:
                await session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred during password reset token.",
                )

        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    async with db as session:
        user_result = await session.execute(
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == user_data.email)
        )
        user = user_result.scalar_one_or_none()

        if not user or not user.password_reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        if (
            user.password_reset_token.token != user_data.token
            or user.password_reset_token.expires_at.replace(
                tzinfo=timezone.utc
            )
            < datetime.now(timezone.utc)
        ):
            await session.delete(user.password_reset_token)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        try:
            # use user.password setter in UserModel to validate and hash password
            user.password = user_data.password
            await session.delete(user.password_reset_token)
            await session.commit()
            return MessageResponseSchema(
                message="Password reset successfully."
            )
        except Exception:
            await session.rollback()
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
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    async with db as session:
        user_result = await session.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        user = user_result.scalar_one_or_none()

        if not user or not user.verify_password(user_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        payload = {"user_id": user.id, "email": user.email}

        try:
            access_token = jwt_manager.create_access_token(payload)
            refresh_token = jwt_manager.create_refresh_token(payload)
            refresh_token_db = RefreshTokenModel.create(
                user_id=user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token,
            )
            session.add(refresh_token_db)
            await session.commit()
            return UserLoginResponseSchema(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
            )
        except Exception:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request.",
            )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    refresh_token_result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )
    refresh_token_db = refresh_token_result.scalar_one_or_none()
    if not refresh_token_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == decoded_token["user_id"])
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(decoded_token)

    return TokenRefreshResponseSchema(
        access_token=access_token,
    )
