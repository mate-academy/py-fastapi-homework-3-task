from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from crud.accounts import get_user_by_email
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from schemas.accounts import (
    DetailResponseSchema,
    MessageResponseSchema,
    ResetPassword,
    TokenPasswordRefresh,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, remove_token

router = APIRouter()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "model": DetailResponseSchema,
            "description": "User already exists",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "Error occurred",
        },
    },
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
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
                detail="User group not found.",
            )
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        token = ActivationTokenModel(user=user)
        db.add(token)
        await db.commit()
        return user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/")
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(
        timezone.utc
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=dict)
async def password_reset_token(
    model: TokenPasswordRefresh, db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, model.email)
    if user and user.is_active:
        old_tokens = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        for token in old_tokens.scalars().all():
            await db.delete(token)
        await db.commit()
        new_refresh_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_refresh_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=dict, status_code=200)
async def password_reset_compleat(
    model: ResetPassword, db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_user_by_email(db, model.email)
        check_token = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.token == model.token
            )
        )
        if user is None:
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        db_check_token = check_token.scalar_one_or_none()
        if db_check_token is None:
            await remove_token(db, user)
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        expires_at = db_check_token.expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await remove_token(db, user)
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if expires_at < datetime.now(timezone.utc):
            await remove_token(db, user)
            raise HTTPException(status_code=400, detail="Expired token.")
        await db.delete(db_check_token)
        new_pass = hash_password(model.password)
        user._hashed_password = new_pass
        await db.commit()
        await db.refresh(user)

        return {"message": "Password reset successfully."}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema,
)
async def user_login(
    request_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    if not user or not user.verify_password(request_data.password):
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
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = payload.get("user_id")

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    token_record = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )
    new_refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id, "email": user.email},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )

    return TokenRefreshResponseSchema(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )
