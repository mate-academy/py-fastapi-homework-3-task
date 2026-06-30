from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from config import get_settings, get_jwt_auth_manager
from config.settings import BaseAppSettings
from database import get_db
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter(tags=["Accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    query = select(UserModel).where(func.lower(UserModel.email) == body.email.lower())
    result = await db.execute(query)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {body.email} already exists.",
        )

    try:
        group_query = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        group_result = await db.execute(group_query)
        group = group_result.scalar_one()

        new_user = UserModel.create(
            email=body.email, raw_password=body.password, group_id=cast(int, group.id)
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)
        await db.commit()
        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK
)
async def activate_account(
    body: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    query = (
        select(ActivationTokenModel)
        .join(UserModel)
        .where(
            func.lower(UserModel.email) == body.email.lower(),
            ActivationTokenModel.token == body.token,
        )
    )
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user_query = select(UserModel).where(UserModel.id == token_record.user_id)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one()

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    body: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    success_response = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    query = select(UserModel).where(func.lower(UserModel.email) == body.email.lower())
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return success_response

    old_tokens_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    old_tokens_result = await db.execute(old_tokens_query)
    for old_token in old_tokens_result.scalars():
        await db.delete(old_token)

    new_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(new_token)
    await db.commit()

    return success_response


@router.post("/reset-password/complete/")
async def complete_password_reset(
    body: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_query = select(UserModel).where(
        func.lower(UserModel.email) == body.email.lower()
    )
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    if not token_record or token_record.token != body.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if datetime.now(timezone.utc) > token_record.expires_at.replace(
        tzinfo=timezone.utc
    ):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user.password = body.password
    await db.delete(token_record)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
    body: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    query = select(UserModel).where(func.lower(UserModel.email) == body.email.lower())
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(body.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    token_payload = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(token_payload)
    refresh_token = jwt_manager.create_refresh_token(token_payload)

    refresh_token_model = RefreshTokenModel.create(
        user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
    )
    db.add(refresh_token_model)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_tokens(
    body: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        decoded = jwt_manager.decode_refresh_token(body.refresh_token)
        user_id = decoded["user_id"]
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    query = select(RefreshTokenModel).where(
        RefreshTokenModel.token == body.refresh_token
    )
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_query = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    new_refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})

    await db.delete(token_record)
    await db.flush()

    new_refresh_token_model = RefreshTokenModel.create(
        user_id=user_id, days_valid=settings.LOGIN_TIME_DAYS, token=new_refresh_token
    )
    db.add(new_refresh_token_model)
    await db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }
