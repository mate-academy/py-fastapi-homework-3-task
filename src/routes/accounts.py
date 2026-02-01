from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pyexpat.errors import messages
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings, settings
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
from schemas.accounts import UserRegistrationResponseSchema, \
    UserRegistrationRequestSchema, AccountActivationRequestSchema, \
    MessageResponseSchema, UserBase, PasswordChangingRequestScheme, \
    TokenVerificationSchema, LoginResponseSchema, AccessTokenResponseSchema, \
    RefreshTokenRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


async def get_user_by_email(db: Annotated[AsyncSession, Depends(get_db)],
                            email: str):
    return await db.scalar(select(UserModel).where(UserModel.email == email))


@router.post("/register/",
             response_model=UserRegistrationResponseSchema,
             status_code=status.HTTP_201_CREATED)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
):
    existing_user = await get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        user_group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )

        new_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
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
            detail="An error occurred during user creation.",
        )

    return new_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(db: Annotated[AsyncSession, Depends(get_db)],
                           user_data: AccountActivationRequestSchema):
    user = await get_user_by_email(db, user_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    if user.is_active:
        raise HTTPException(status_code=400,
                            detail="User account is already active.")
    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == user_data.token,
        )
    )
    activation_token = result.scalar_one_or_none()
    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(db: Annotated[AsyncSession, Depends(get_db)],
                                 user_data: UserBase):
    try:
        user = await get_user_by_email(db, user_data.email)
        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            new_token = PasswordResetTokenModel(user_id=user.id)
            db.add(new_token)

            await db.commit()

    except SQLAlchemyError:
        await db.rollback()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_completion(
        db: Annotated[AsyncSession, Depends(get_db)],
        user_data: PasswordChangingRequestScheme):
    user = await get_user_by_email(db, user_data.email)

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == user_data.token,
        )
    )
    reset_token = result.scalar_one_or_none()
    if not reset_token:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    expires_at = cast(datetime, reset_token.expires_at).replace(
        tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    try:
        user.password = user_data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=LoginResponseSchema, status_code=201)
async def login(db: Annotated[AsyncSession, Depends(get_db)],
                jwt_manager: Annotated[
                    JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
                user_data: UserRegistrationRequestSchema, ):
    db_user = await get_user_by_email(db, user_data.email)

    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    token_data = {
        "user_id": db_user.id,
        "email": db_user.email,
    }

    access_token = jwt_manager.create_access_token(data=token_data)
    refresh_token = jwt_manager.create_refresh_token(data=token_data)

    refresh_token_obj = RefreshTokenModel.create(
        user_id=db_user.id,
        days_valid=7,
        token=refresh_token,
    )

    try:
        db.add(refresh_token_obj)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return LoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
async def refresh_access_token(
        payload: RefreshTokenRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    refresh_token = payload.refresh_token

    try:
        token_data = jwt_manager.decode_refresh_token(refresh_token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    user_id = token_data.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token payload.",
        )

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token)
    )
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    result = await db.execute(
        select(UserModel).where(UserModel.id == int(user_id)))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token(
        data={
            "user_id": user.id,
            "email": user.email,
        }
    )

    return AccessTokenResponseSchema(access_token=new_access_token)
