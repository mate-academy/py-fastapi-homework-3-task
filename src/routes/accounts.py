from datetime import datetime, timezone, timedelta
from typing import cast

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
from security.passwords import PasswordManager
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    UserLoginSchema,
    TokenResponseSchema
)

router = APIRouter()
password_manager = PasswordManager()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    existing_user = (await db.execute(stmt)).scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    user_group = (await db.execute(group_stmt)).scalars().first()

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id if user_group else 1
        )
        new_user.is_active = False

        db.add(new_user)
        await db.flush()

        expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        token_val = password_manager.generate_token() if hasattr(password_manager, "generate_token") else "some-secure-token"

        activation_token = ActivationTokenModel(
            token=token_val,
            expires_at=expires_at,
            user_id=cast(int, new_user.id)
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except ValueError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return new_user


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
        activation_data: UserActivationSchema,
        db: AsyncSession = Depends(get_db)
):
    user_stmt = select(UserModel).where(UserModel.email == activation_data.email)
    user = (await db.execute(user_stmt)).scalars().first()

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

    token_stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == activation_data.token
    )
    token_record = (await db.execute(token_stmt)).scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    success_message = {"message": "If you are registered, you will receive an email with instructions."}

    user_stmt = select(UserModel).where(UserModel.email == reset_data.email)
    user = (await db.execute(user_stmt)).scalars().first()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        token_val = password_manager.generate_token() if hasattr(password_manager, "generate_token") else "reset-secure-token"

        reset_token = PasswordResetTokenModel(
            token=token_val,
            expires_at=expires_at,
            user_id=cast(int, user.id)
        )
        db.add(reset_token)
        await db.commit()

    return success_message


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
        complete_data: PasswordResetCompleteSchema,
        db: AsyncSession = Depends(get_db)
):
    user_stmt = select(UserModel).where(UserModel.email == complete_data.email)
    user = (await db.execute(user_stmt)).scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == complete_data.token
    )
    token_record = (await db.execute(token_stmt)).scalars().first()

    if not token_record:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = complete_data.password

        await db.delete(token_record)
        await db.commit()
        await db.refresh(user)
    except ValueError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=TokenResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
        login_data: UserLoginSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user_stmt = select(UserModel).where(UserModel.email == login_data.email)
    user = (await db.execute(user_stmt)).scalars().first()

    is_valid = False
    if user:
        is_valid = user.verify_password(login_data.password)

    if not user or not is_valid:
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
        token_payload = {"user_id": cast(int, user.id)}
        access_token = jwt_manager.create_access_token(token_payload)
        refresh_token = jwt_manager.create_refresh_token(token_payload)

        db_refresh_token = RefreshTokenModel(
            token=refresh_token,
            user_id=cast(int, user.id),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )

        db.add(db_refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_token(
        refresh_token_data: dict,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    token_str = refresh_token_data.get("refresh_token")
    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is required."
        )

    try:
        payload = jwt_manager.decode_refresh_token(token_str)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == token_str)
    db_token = (await db.execute(stmt)).scalars().first()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_id = payload.get("sub") or payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload.")

    user_stmt = select(UserModel).where(UserModel.id == int(user_id))
    user = (await db.execute(user_stmt)).scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"user_id": int(user_id)})

    return {
        "access_token": new_access_token,
        "refresh_token": token_str,
        "token_type": "bearer"
    }
