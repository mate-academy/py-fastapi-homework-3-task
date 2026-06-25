from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
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
async def register_new_user(
    user_data: UserRegistrationRequestSchema,
    session: Annotated[AsyncSession, Depends(get_db)],
):
    db_user = await session.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = db_user.scalar_one_or_none()

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group_user_result = await session.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group_user = group_user_result.scalar_one_or_none()

    if group_user is None:
        group_user = UserGroupModel(name=UserGroupEnum.USER)
        session.add(group_user)

        await session.flush()

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group_user.id,
        )

        session.add(new_user)
        await session.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        session.add(activation_token)

        await session.commit()
        await session.refresh(new_user)
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return new_user


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK
)
async def activate_account(
    activation_data: UserActivationRequestSchema,
    session: Annotated[AsyncSession, Depends(get_db)],
):
    result = await session.execute(
        select(UserModel).where(UserModel.email == activation_data.email)
    )
    db_user = result.scalar_one_or_none()

    token_result = await session.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token
        )
    )

    activation_token = token_result.scalar_one_or_none()

    if (
        db_user is None
        or activation_token is None
        or db_user.id != activation_token.user_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    db_user.is_active = True
    await session.delete(activation_token)
    await session.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password_token(
    email: PasswordResetRequestSchema, session: Annotated[AsyncSession, Depends(get_db)]
):
    result_user = await session.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == email.email)
    )

    message_response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = result_user.scalar_one_or_none()

    if user is None or not user.is_active:
        return message_response

    if user.password_reset_token is not None:
        await session.delete(user.password_reset_token)

    new_password_reset_token_model = PasswordResetTokenModel(user_id=user.id)

    session.add(new_password_reset_token_model)
    await session.commit()

    return message_response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema,
    session: Annotated[AsyncSession, Depends(get_db)],
):
    result_user = await session.execute(
        select(UserModel).where(UserModel.email == data.email)
    )

    user = result_user.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    result_token = await session.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    token = result_token.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    if token.token != data.token:
        await session.delete(token)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await session.delete(token)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user.password = data.password
        await session.delete(token)
        await session.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
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
    session: Annotated[AsyncSession, Depends(get_db)],
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
    settings: Annotated[BaseAppSettings, Depends(get_settings)],
):
    result_user = await session.execute(
        select(UserModel).where(UserModel.email == credentials.email)
    )

    user = result_user.scalar_one_or_none()

    if user is None or not user.verify_password(credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})
    access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    try:
        refresh_token_model = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        session.add(refresh_token_model)
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
    status_code=status.HTTP_200_OK,
)
async def access_token_refresh(
    data: TokenRefreshRequestSchema,
    session: Annotated[AsyncSession, Depends(get_db)],
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(token=data.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    result_token = await session.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )

    token = result_token.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_id = decoded_token["user_id"]

    if token.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    result_user = await session.execute(
        select(UserModel).where(UserModel.id == user_id)
    )

    user = result_user.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
