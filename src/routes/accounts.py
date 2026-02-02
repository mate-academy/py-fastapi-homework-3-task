from datetime import datetime, timezone
from typing import Annotated

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from fastapi import APIRouter, Depends, HTTPException, status
from schemas import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from src.exceptions.security import InvalidTokenError, TokenExpiredError

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)]
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    try:
        group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER)
        )
        if not group:
            raise HTTPException(
                status_code=500,
                detail="An error occurred during user creation."
            )
        try:
            new_user = UserModel.create(
                email=user_data.email,
                raw_password=user_data.password,
                group_id=group.id
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(e)
            )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email,
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == user_data.token)
        .options(joinedload(ActivationTokenModel.user))
    )
    token_obj = result.scalar_one_or_none()

    is_valid = True
    if not token_obj:
        is_valid = False
    elif token_obj.expires_at.replace(tzinfo=timezone.utc) < datetime.now(
            timezone.utc):
        is_valid = False
    elif token_obj.user.email != user_data.email:
        is_valid = False

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    db_user = token_obj.user

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    try:
        db_user.is_active = True
        await db.delete(token_obj)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during activation."
        )
    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def request_password_reset(
        user_data: PasswordResetRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    success_message = MessageResponseSchema(
        message=("If you are registered, "
                 "you will receive an email with instructions.")
    )

    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(joinedload(UserModel.password_reset_token))
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        return success_message

    try:
        if db_user.password_reset_token:
            await db.delete(db_user.password_reset_token)
            await db.flush()

        new_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_reset_token)

        await db.commit()

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset request."
        )

    return success_message


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def request_password_reset_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(joinedload(UserModel.password_reset_token))
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    existed_token = db_user.password_reset_token

    if not existed_token or existed_token.token != user_data.token:
        if existed_token:
            await db.delete(existed_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if existed_token.expires_at.timestamp() < datetime.now(
            timezone.utc).timestamp():
        await db.delete(existed_token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        db_user.hashed_password = hash_password(user_data.password)
        await db.delete(existed_token)
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
        user_data: UserLoginRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        settings: Annotated[BaseAppSettings, Depends(get_settings)],
) -> UserLoginResponseSchema:
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    token_data = {
        "sub": str(db_user.id),
        "user_id": db_user.id,
        "email": user_data.email,
    }
    try:
        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)

        db_refresh_token = RefreshTokenModel.create(
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
            user_id=db_user.id
        )
        db.add(db_refresh_token)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=TokenRefreshResponseSchema
)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except (InvalidTokenError, BaseSecurityError, TokenExpiredError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_id = payload.get("user_id")

    token_result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token)
    )
    db_token = token_result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == int(user_id)))
    db_user = user_result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        data={
            "sub": str(db_user.id),
            "user_id": db_user.id,
            "email": db_user.email}
    )
    return TokenRefreshResponseSchema(access_token=new_access_token)
