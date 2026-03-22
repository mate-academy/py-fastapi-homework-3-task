from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from security.interfaces import JWTAuthManagerInterface

from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


def to_utc_timezone(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    payload: UserRegistrationRequestSchema,
    session: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    query_existing = select(UserModel).where(UserModel.email == str(payload.email))
    res_existing = await session.execute(query_existing)
    if res_existing.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {payload.email} already exists.",
        )

    query_group = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    res_group = await session.execute(query_group)
    target_group = res_group.scalars().first()
    if target_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    try:
        new_account = UserModel.create(
            email=str(payload.email),
            raw_password=payload.password,
            group_id=cast(int, target_group.id),
        )
        session.add(new_account)
        await session.flush()

        activation_rec = ActivationTokenModel(user_id=cast(int, new_account.id))
        session.add(activation_rec)

        await session.commit()
        await session.refresh(new_account)

    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(
        id=cast(int, new_account.id), email=new_account.email
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate_user_account(
    payload: UserActivationRequestSchema,
    session: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    query_user = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == str(payload.email))
    )
    res_user = await session.execute(query_user)
    account = res_user.scalars().first()

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if account.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    query_token = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == cast(int, account.id),
        ActivationTokenModel.token == payload.token,
    )
    res_token = await session.execute(query_token)
    token_record = res_token.scalars().first()
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expiry = to_utc_timezone(cast(datetime, token_record.expires_at))
    if expiry <= datetime.now(timezone.utc):
        await session.delete(token_record)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    account.is_active = True
    await session.delete(token_record)
    await session.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset_token(
    payload: PasswordResetRequestSchema,
    session: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    query_user = select(UserModel).where(UserModel.email == str(payload.email))
    res_user = await session.execute(query_user)
    account = res_user.scalars().first()

    if account is not None and account.is_active:
        await session.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == cast(int, account.id)
            )
        )
        reset_token = PasswordResetTokenModel(user_id=cast(int, account.id))
        session.add(reset_token)
        try:
            await session.commit()
        except SQLAlchemyError:
            await session.rollback()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    session: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    query_user = select(UserModel).where(UserModel.email == str(payload.email))
    res_user = await session.execute(query_user)
    account = res_user.scalars().first()
    if account is None or not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    query_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == cast(int, account.id)
    )
    res_token = await session.execute(query_token)
    token_record = res_token.scalars().first()

    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    expiry = to_utc_timezone(cast(datetime, token_record.expires_at))
    if token_record.token != payload.token or expiry <= datetime.now(timezone.utc):
        await session.delete(token_record)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        account.password = payload.password
        await session.delete(token_record)
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    payload: UserLoginRequestSchema,
    session: AsyncSession = Depends(get_db),
    app_settings: BaseAppSettings = Depends(get_settings),
    jwt_auth: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> UserLoginResponseSchema:
    query_user = select(UserModel).where(UserModel.email == str(payload.email))
    res_user = await session.execute(query_user)
    account = res_user.scalars().first()

    if account is None or not account.verify_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not account.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_auth.create_access_token({"user_id": cast(int, account.id)})

    refresh_token = jwt_auth.create_refresh_token(
        {"user_id": cast(int, account.id)},
        expires_delta=timedelta(days=cast(int, app_settings.LOGIN_TIME_DAYS)),
    )

    refresh_rec = RefreshTokenModel.create(
        user_id=cast(int, account.id),
        days_valid=cast(int, app_settings.LOGIN_TIME_DAYS),
        token=refresh_token,
    )
    session.add(refresh_rec)

    try:
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    session: AsyncSession = Depends(get_db),
    jwt_auth: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        token_data = jwt_auth.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    uid = cast(int, token_data.get("user_id"))

    query_refresh = select(RefreshTokenModel).where(
        RefreshTokenModel.token == payload.refresh_token
    )
    res_refresh = await session.execute(query_refresh)
    refresh_rec = res_refresh.scalars().first()

    if refresh_rec is None or refresh_rec.user_id != uid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    query_user = select(UserModel).where(UserModel.id == uid)
    res_user = await session.execute(query_user)
    account = res_user.scalars().first()

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_auth.create_access_token({"user_id": uid})
    return TokenRefreshResponseSchema(access_token=new_access_token)
