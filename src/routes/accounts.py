from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
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
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


@router.post(
    "/register/", response_model=UserRegistrationResponseSchema, status_code=201
)
async def register_user(
        data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {data.email} already exists."
        )

    group_result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = group_result.scalar_one()
    new_password = data.password
    new_user = UserModel.create(
        email=data.email,
        raw_password=new_password,
        group_id=user_group.id,
    )

    db.add(new_user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=new_user.id)
    db.add(activation_token)

    await db.flush()

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(500, "An error occurred during user creation.")

    await db.refresh(new_user)
    return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)


@router.post("/activate/", status_code=200)
async def activate_user(
    data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == data.email)
    )
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token"
        )
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    activation_token = db_user.activation_token

    if not activation_token or activation_token.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    expires_at_aware = activation_token.expires_at.replace(tzinfo=timezone.utc)

    if expires_at_aware < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True
    await db.delete(db_user.activation_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200)
async def password_reset_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )

    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    if db_user.password_reset_token:
        await db.delete(db_user.password_reset_token)

        await db.commit()

    new_password_reset_token = PasswordResetTokenModel(user_id=db_user.id)
    db.add(new_password_reset_token)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )

    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_obj = db_user.password_reset_token

    expires_at_aware = token_obj.expires_at.replace(tzinfo=timezone.utc)
    if (
        not token_obj
        or token_obj.token != data.token
        or expires_at_aware < datetime.now(timezone.utc)
    ):
        if token_obj:
            await db.delete(db_user.password_reset_token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    db_user.password = data.password
    try:
        db.add(db_user)
        await db.delete(token_obj)
        await db.commit()
        await db.refresh(db_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully.", "new_info": db_user}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    jwt_payload = {
        "user_id": db_user.id,
        "email": db_user.email
    }
    if not db_user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token(jwt_payload)
    refresh_token = jwt_manager.create_refresh_token(jwt_payload)

    refresh_token_obj = RefreshTokenModel.create(
        user_id=db_user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
    )
    try:
        db.add(refresh_token_obj)
        await db.commit()
    except Exception:
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),

):
    try:
        decode_refresh_token = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )

    refresh_token = token_result.scalar_one_or_none()
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == refresh_token.user_id)
    )
    db_user = user_result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if decode_refresh_token["user_id"] != refresh_token.user_id:
        raise HTTPException(status_code=400, detail="Token has expired.")

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
