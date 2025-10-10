from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

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

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivateRequestSchema,
    EmailSchema,
    CompletePasswordResetRequestSchema,
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
async def create_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    try:
        db_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if db_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        user_group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        token = ActivationTokenModel(user=new_user)
        db.add(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    user_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
) -> UserLoginResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id, "email": user.email},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )

    try:
        new_refresh_token = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(new_refresh_token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
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
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    data: UserActivateRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    if not token or token.token != data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    data: EmailSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    message_response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user or user.is_active is False:
        return message_response

    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    new_token = PasswordResetTokenModel(user_id=user.id)
    db.add(new_token)
    await db.commit()
    return message_response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    data: CompletePasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
        if not user or user.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        reset_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        if (
            not reset_token
            or reset_token.token != data.token
            or reset_token.expires_at.replace(tzinfo=timezone.utc)
            < datetime.now(timezone.utc)
        ):
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
        user.password = data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> TokenRefreshResponseSchema:
    try:
        try:
            decoded_refresh_token = jwt_manager.decode_refresh_token(data.refresh_token)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
            )

        user_id = decoded_refresh_token.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
            )

        refresh_token = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == data.refresh_token
            )
        )

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        return TokenRefreshResponseSchema(access_token=access_token)

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
