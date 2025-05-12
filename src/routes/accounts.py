from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
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
    UserResponseSchema,
    UserRegistrationRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginResponseSchema,
    PasswordResetCompleteRequestSchema,
)
from schemas.accounts import (
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    UserLoginRequestSchema,
    PasswordResetRequestWithTokenResponse,
)
from security.interfaces import JWTAuthManagerInterface
from core.security import hash_password, pwd_context

router = APIRouter()


@router.post(
    "/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema, session: AsyncSession = Depends(get_db)
):
    try:
        result = await session.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        existing_user = result.scalar_one_or_none()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group_result = await session.execute(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER.value
            )
        )
        user_group = group_result.scalar_one_or_none()
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User group not found in database.",
            )

        hashed_password = hash_password(user_data.password)

        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_password,
            is_active=False,
            group=user_group,
        )
        session.add(new_user)
        await session.flush()

        activation_token = ActivationTokenModel(
            user_id=new_user.id,
        )

        session.add(activation_token)
        await session.flush()
        await session.commit()

        return UserResponseSchema(id=new_user.id, email=new_user.email)

    except HTTPException:
        raise
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/")
async def activate_user_account(
    activation_data: UserActivationRequestSchema,
    session: AsyncSession = Depends(get_db),
):
    try:
        result = await session.execute(
            select(ActivationTokenModel)
            .options(joinedload(ActivationTokenModel.user))
            .join(UserModel)
            .where(
                UserModel.email == activation_data.email,
                ActivationTokenModel.token == activation_data.token,
            )
        )
        token = result.scalars().first()

        now_utc = datetime.now(timezone.utc)
        if (
            not token
            or cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < now_utc
        ):
            if token:
                await session.delete(token)
                await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user = token.user

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        user.is_active = True

        await session.delete(token)
        await session.commit()

        return {"message": "User account activated successfully."}

    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Server error: {str(e)}",
        )


@router.post("/password-reset/request/")
async def request_password_reset_token(
    data: PasswordResetRequestSchema, session: AsyncSession = Depends(get_db)
):
    try:
        result = await session.execute(
            select(UserModel).where(UserModel.email == data.email)
        )
        user = result.scalar_one_or_none()

        if user and user.is_active:
            await session.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            reset_token = PasswordResetTokenModel(user_id=user.id)
            session.add(reset_token)
            await session.commit()

            return PasswordResetRequestWithTokenResponse(
                message="If you are registered, you will receive an email with instructions.",
                token=reset_token.token,
            )

    except Exception:
        await session.rollback()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
    reset_data: PasswordResetCompleteRequestSchema,
    session: AsyncSession = Depends(get_db),
):
    try:
        result = await session.execute(
            select(PasswordResetTokenModel)
            .options(joinedload(PasswordResetTokenModel.user))
            .join(UserModel)
            .where(
                PasswordResetTokenModel.token == reset_data.token,
                UserModel.email == reset_data.email,
            )
        )
        token_obj = result.scalars().first()

        now_utc = datetime.now(timezone.utc)
        if (
            not token_obj
            or token_obj.token != reset_data.token
            or token_obj.expires_at.replace(tzinfo=timezone.utc) < now_utc
        ):
            delete_stmt = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user.has(email=reset_data.email)
            )
            await session.execute(delete_stmt)
            await session.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user = token_obj.user
        if not user or not user.is_active:
            await session.delete(token_obj)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        new_hashed = hash_password(reset_data.password)
        user._hashed_password = new_hashed

        await session.delete(token_obj)
        await session.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
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
    credentials: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    # Отримуємо користувача з БД
    result = await db.execute(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(credentials.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    # Генеруємо токени
    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    # Зберігаємо refresh-token у БД
    try:
        rt = RefreshTokenModel(user_id=user.id, token=refresh_token)
        db.add(rt)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    refresh_token = payload.refresh_token

    # 1. Декодуємо та перевіряємо refresh-токен
    try:
        decoded_token = jwt_manager.decode_refresh_token(token=refresh_token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    # У тестах очікують ключ "user_id" в payload
    user_id = decoded_token.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload."
        )

    # 2. Перевіряємо наявність токена в БД
    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token)
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    # 3. Шукаємо користувача
    result_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result_user.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    # 4. Генеруємо новий access токен з тим же ключем user_id
    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
