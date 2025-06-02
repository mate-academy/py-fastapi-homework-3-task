import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
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
    RefreshTokenModel
)
from exceptions import InvalidTokenError, TokenExpiredError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, UserActivationRequestSchema
from schemas.accounts import UserLoginRequestSchema, UserLoginResponseSchema, MessageResponseSchema, UserBase, \
    PasswordResetCompleteRequestSchema, RefreshTokenResponseSchema, RefreshTokenRequestSchema
from security.interfaces import JWTAuthManagerInterface
router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    user_group = await db.scalar(
        select(
            UserGroupModel
        ).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return new_user

@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )
    try:
        token_obj = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(token_obj)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_user(activation_data: UserActivationRequestSchema,
                        db: AsyncSession = Depends(get_db)):
    query = (select(UserModel).options(joinedload(UserModel.activation_token)).where(UserModel.email==activation_data.email))

    result = await db.execute(query)

    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account is already active")

    if not user.activation_token or user.activation_token.token != activation_data.token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    expires_at = user.activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    user.is_active = True

    await db.delete(user.activation_token)

    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/")
async def password_reset(user_data: UserBase,
                         db: AsyncSession = Depends(get_db)) -> MessageResponseSchema:
    query = select(UserModel).where(UserModel.email==user_data.email)
    result = await db.execute(query)
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(
            PasswordResetTokenModel.__table__.delete().where(PasswordResetTokenModel.user_id==user.id)
        )

        token = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        new_token = PasswordResetTokenModel(user_id=user.id,
                                            token=token,
                                            expires_at=expires_at)

        db.add(new_token)

        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/")
async def reset_password(user_data: PasswordResetCompleteRequestSchema,
                         db: AsyncSession = Depends(get_db)) -> MessageResponseSchema:
    query = select(UserModel).where(UserModel.email==user_data.email)
    result = await db.execute(query)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token")

    query_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id,
                                                        PasswordResetTokenModel.token == user_data.token)
    result_token = await db.execute(query_token)

    token_obj = result_token.scalars().first()

    if not token_obj:

        some_token_query = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id==user_data.id)
        some_token_result = await db.execute(some_token_query)
        some_token_obj = some_token_result.scalars().first()
        if some_token_obj:
            await db.delete(some_token_obj)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token")

    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_obj)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = user_data.password
        await db.delete(token_obj)
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


@router.post("/refresh/")
async def refresh_token(
        token_data: RefreshTokenRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> RefreshTokenResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(
            token_data.refresh_token
        )

        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid refresh token."
            )

        query = select(
            RefreshTokenModel
        ).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
        result = await db.execute(query)
        token_record = result.scalars().first()

        if not token_record:
            raise HTTPException(
                status_code=401,
                detail="Refresh token not found."
            )

        query_user = select(
            UserModel
        ).where(
            UserModel.id == user_id
        )
        result_user = await db.execute(query_user)
        user = result_user.scalars().first()

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="User account is not active."
            )

        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Token has expired."
            )

        access_token = jwt_manager.create_access_token(
            {"user_id": user.id}
        )

        return RefreshTokenResponseSchema(
            access_token=access_token
        )

    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token."
        )
