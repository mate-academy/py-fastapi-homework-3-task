import secrets
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    RefreshTokenModel, PasswordResetTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError

from schemas import UserRegistrationRequestSchema
from schemas.accounts import (
    UserResponseSchema,
    UserActivationRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    AccessTokenResponseSchema,
    RefreshTokenRequestSchema, PasswordResetCompleteSchema, PasswordResetRequestSchema
)

from security.interfaces import JWTAuthManagerInterface


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

router = APIRouter()


@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    existing_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_query = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_query)
        user_group = group_result.scalar_one_or_none()

        if not user_group:
            raise Exception("Default user group not found in database.")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )
        db.add(new_user)

        await db.flush()

        token_str = secrets.token_urlsafe(32)
        new_token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=token_str
        )
        db.add(new_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        await db.rollback()
        print(f"Registration Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):

    user_query = select(UserModel).where(UserModel.email == data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

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
        ActivationTokenModel.token == data.token,
        ActivationTokenModel.user_id == cast(int, user.id)
    )
    result = await db.execute(token_query)

    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    db_expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if db_expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:
        user.is_active = True

        await db.delete(token_record)

        await db.commit()
        return {"message": "User account activated successfully."}

    except Exception as e:
        await db.rollback()
        print(f"Activation Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        payload: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):

    query = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(payload.password):
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
        token_data = {"user_id": user.id}
        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)

        new_refresh_token = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(new_refresh_token)

        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    except Exception as e:
        await db.rollback()
        print(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/api/v1/accounts/refresh/", response_model=AccessTokenResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
    payload: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_data = jwt_manager.decode_refresh_token(payload.refresh_token)
        user_id_str = decoded_data.get("user_id")
        if not user_id_str:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload.")
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token.")

    token_query = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    token_result = await db.execute(token_query)
    db_token = token_result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_query = select(UserModel).where(UserModel.id == cast(int, db_token.user_id))
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return {"access_token": new_access_token}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    success_message = {
        "message": "If you are registered, you will receive an email with instructions.",
        "code": status.HTTP_200_OK,
    }

    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == cast(int, user.id)
                )
            )

            new_reset_token = PasswordResetTokenModel(
                user_id=cast(int, user.id)
            )
            db.add(new_reset_token)

            await db.commit()

        except Exception as e:
            await db.rollback()
            print(f"Error creating reset token: {e}")
            return success_message

    return success_message


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
        data: PasswordResetCompleteSchema,
        db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).where(UserModel.email == data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == cast(int, user.id)
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    async def invalidate_and_raise():
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if not token_record or token_record.token != data.token:
        await invalidate_and_raise()

    db_expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if db_expires_at < datetime.now(timezone.utc):
        await invalidate_and_raise()

    try:
        user.password = data.password

        await db.delete(token_record)

        await db.commit()
        return {"message": "Password reset successfully."}

    except ValueError as ve:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        await db.rollback()
        print(f"Password reset error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
