from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, and_
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
    RefreshTokenModel
)
from database.models.accounts import UserProfileModel
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    UserLoginResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == user_data.email.lower())
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group_query = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_query)
    user_group = group_result.scalar_one_or_none()

    if not user_group:
        raise HTTPException(status_code=500, detail="Default user group not found")

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(new_user)
        await db.flush()

        new_profile = UserProfileModel(
            user_id=new_user.id,
            first_name=user_data.first_name,
            last_name=user_data.last_name
        )
        db.add(new_profile)

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).where(UserModel.email == user_data.email.lower())
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_query = select(ActivationTokenModel).where(
        and_(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == user_data.token,
            ActivationTokenModel.expires_at > datetime.now(timezone.utc)
        )
    )
    result = await db.execute(token_query)
    activation_token = result.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True

        await db.execute(
            delete(ActivationTokenModel)
            .where(ActivationTokenModel.id == activation_token.id)
        )

        await db.commit()

        return {"message": "User account activated successfully."}

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the account."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(UserModel.email == reset_data.email.lower())
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        try:
            # Удаляем все существующие токены для этого пользователя
            delete_query = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            await db.execute(delete_query)
            await db.flush()

            # Создаем новый токен сброса пароля
            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)
            await db.commit()

        except SQLAlchemyError:
            await db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(UserModel.email == reset_data.email.lower())
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_query = select(PasswordResetTokenModel).where(
        and_(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == reset_data.token,
            PasswordResetTokenModel.expires_at > datetime.now(timezone.utc)
        )
    )
    result = await db.execute(token_query)
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = reset_data.password

        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.id == reset_token.id)
        )

        await db.commit()
        return {"message": "Password reset successfully."}

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    query = select(UserModel).where(UserModel.email == login_data.email.lower())
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token(
            data={"user_id": user.id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        refresh_token = jwt_manager.create_refresh_token(
            data={"user_id": user.id}
        )

        refresh_token_model = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.REFRESH_TOKEN_EXPIRE_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_model)
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
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        refresh_token = token_data.refresh_token

        try:
            decoded_token = jwt_manager.decode_refresh_token(refresh_token)
        except BaseSecurityError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

        token_query = select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token
        )
        result = await db.execute(token_query)
        db_refresh_token = result.scalar_one_or_none()

        if not db_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        user_id = decoded_token.get("user_id") or int(decoded_token.get("sub"))

        user_query = select(UserModel).where(UserModel.id == user_id)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        access_token = jwt_manager.create_access_token(
            data={"user_id": user.id}
        )

        return {"access_token": access_token}

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token"
        )
