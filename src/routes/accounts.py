from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    MessageResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Register a new user with an email and password, and create an activation token for the account.",
    responses={
        409: {
            "description": "Conflict - A user with this email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email test@example.com already exists."}
                }
            },
        },
        500: {
            "description": "Internal Server Error - An error occurred during user creation.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result = await db.execute(stmt)
    user_group = result.scalars().first()

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return new_user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Activate a user account",
    description="Activate a user's account using a valid activation token.",
    responses={
        400: {
            "description": "Bad Request - The activation token is invalid or expired, "
                            "or the account is already active.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid or expired activation token."}
                }
            },
        },
    },
)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    stmt = (
        select(ActivationTokenModel)
        .join(UserModel)
        .where(
            UserModel.email == activation_data.email,
            ActivationTokenModel.token == activation_data.token,
        )
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if activation_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = activation_token.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Request a password reset token",
    description="Request a password reset token for an active user account. "
)
async def request_password_reset_token(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    try:
        if user and user.is_active:
            stmt = select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            result = await db.execute(stmt)
            existing_token = result.scalars().first()

            if existing_token:
                await db.delete(existing_token)

            reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
            db.add(reset_token)

            await db.commit()
    except SQLAlchemyError:
        await db.rollback()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )
