from datetime import (
    datetime,
    timezone
)

from typing import cast

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status
)

from sqlalchemy import (
    select,
    delete
)

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import (
    get_jwt_auth_manager,
    get_settings,
    BaseAppSettings
)

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
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserResponseSchema,
    ActivateUserRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshTokenRequestSchema,
    RefreshTokenResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        stmt_existing = (
            select(UserModel).
            where(UserModel.email == user_data.email)
        )
        res_existing = await db.execute(stmt_existing)
        if res_existing.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        stmt_group = (
            select(UserGroupModel)
            .where(UserGroupModel.name == UserGroupEnum.USER)
        )
        res_group = await db.execute(stmt_group)
        user_group = res_group.scalars().first()
        if not user_group:
            raise HTTPException(status_code=500, detail="Default user group not found.")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(new_user)
        await db.flush()

        db.add(ActivationTokenModel(user_id=cast(int, new_user.id)))

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    payload: ActivateUserRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt_user = (
        select(UserModel)
        .where(UserModel.email == payload.email)
    )
    res_user = await db.execute(stmt_user)
    user = res_user.scalars().first()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    stmt_token = (
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == user.id)
    )
    res_token = await db.execute(stmt_token)
    token_record = res_token.scalars().first()

    if not token_record or token_record.token != payload.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.execute(
            delete(ActivationTokenModel).
            where(ActivationTokenModel.id == token_record.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.execute(
        delete(ActivationTokenModel)
        .where(ActivationTokenModel.id == token_record.id)
    )
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    msg = {"message": "If you are registered, you will receive an email with instructions."}

    stmt_user = select(UserModel).where(UserModel.email == payload.email)
    res_user = await db.execute(stmt_user)
    user = res_user.scalars().first()

    if not user or not user.is_active:
        return msg

    await db.execute(
        delete(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    db.add(PasswordResetTokenModel(user_id=user.id))
    await db.commit()

    return msg


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        stmt_user = (
            select(UserModel)
            .where(UserModel.email == payload.email)
        )
        res_user = await db.execute(stmt_user)
        user = res_user.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        stmt_token = (
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        res_token = await db.execute(stmt_token)
        token_record = res_token.scalars().first()

        if not token_record:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if token_record.token != payload.token:
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.id == token_record.id)
            )
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        expires_at = token_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.id == token_record.id)
            )
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = payload.password

        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.id == token_record.id)
        )
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=LoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    payload: LoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    stmt_user = select(UserModel).where(UserModel.email == payload.email)
    res_user = await db.execute(stmt_user)
    user = res_user.scalars().first()

    if not user or not user.verify_password(payload.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_record)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post(
    "/refresh/", #CORRECT!!
    response_model=RefreshTokenResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    payload: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        token_data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = token_data.get("user_id")

    stmt_rt = (
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == payload.refresh_token)
    )
    res_rt = await db.execute(stmt_rt)
    rt_record = res_rt.scalars().first()
    if not rt_record:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    res_user = await db.execute(stmt_user)
    user = res_user.scalars().first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": access_token}
