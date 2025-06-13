from datetime import datetime, timedelta
from typing import cast

import sqlalchemy
from fastapi import APIRouter, Depends, HTTPException
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
    RefreshTokenModel
)
from exceptions import TokenExpiredError
from schemas import (UserRegisterResponse, UserRegisterSchema,
                     UserActivationRequestSchema, EmailSchema,
                     UserResetPasswordComplete, UserLoginSchema,
                     UserLoginResponse, RefreshTokenSchema)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


@router.post("/register/", response_model=UserRegisterResponse, status_code=201)
async def register(user_data: UserRegisterSchema, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        is_exists = result.scalar_one_or_none()
        if is_exists:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group_result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        user_group = user_group_result.scalar_one()

        try:
            user = UserModel.create(
                email=user_data.email,
                raw_password=user_data.password,
                group_id=user_group.id
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        db.add(user)

        await db.flush()

        activation_token_model = ActivationTokenModel(user_id=user.id)
        db.add(activation_token_model)

        await db.commit()
        await db.refresh(user)

        return UserRegisterResponse(
            id=user.id,
            email=user.email,
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def user_activate_token(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
        user = result_user.scalar_one_or_none()
        if not user:
            raise HTTPException(
                400, "Invalid or expired activation token."
            )

        result_token = await db.execute(
            select(ActivationTokenModel).where(
                ActivationTokenModel.token == data.token,
                ActivationTokenModel.user_id == user.id
            )
        )

        token = result_token.scalar_one_or_none()

        if not token:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired activation token."
            )

        if user.is_active:
            raise HTTPException(
                status_code=400,
                detail="User account is already active."
            )

        if token.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired activation token."
            )

        user.is_active = True
        await db.delete(token)
        await db.commit()
        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user activation."
        )


@router.post("/password-reset/request/")
async def user_reset_password_request(data: EmailSchema, db: AsyncSession = Depends(get_db)):
    result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result_user.scalar_one_or_none()

    if not user or not user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)

    await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=200)
async def user_reset_password_complete(data: UserResetPasswordComplete, db: AsyncSession = Depends(get_db)):
    try:
        user_result = await db.execute(select(UserModel).where(UserModel.email == data.email))
        user = user_result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        token_result = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        token = token_result.scalar_one_or_none()

        if not token:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        if token.expires_at < datetime.utcnow() or token.token != data.token:
            await db.delete(token)
            await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        try:
            user.password = data.password
        except ValueError:
            raise HTTPException(
                500, "Invalid password."
            )

        await db.delete(token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponse, status_code=201)
async def user_login(
        data: UserLoginSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    try:
        result_user = await db.execute(select(UserModel).where(UserModel.email == data.email))
        user = result_user.scalar_one_or_none()

        if not user or not user.verify_password(data.password):
            raise HTTPException(
                401, "Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                403, "User account is not activated."
            )

        refresh_token_str = jwt_manager.create_refresh_token(
            data={"user_id": user.id},
            expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
        )

        access_token_str = jwt_manager.create_access_token(
            data={"user_id": user.id},
        )

        refresh_token_model = RefreshTokenModel.create(
            token=refresh_token_str,
            days_valid=settings.LOGIN_TIME_DAYS,
            user_id=user.id,
        )
        db.add(refresh_token_model)

        await db.commit()

        return UserLoginResponse(
            access_token=access_token_str,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )
    except sqlalchemy.exc.SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", status_code=200)
async def user_refresh(
    data: RefreshTokenSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = payload.get("user_id")
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid refresh token."
        )

    result_token = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    token = result_token.scalar_one_or_none()

    if not token:
        raise HTTPException(
            401, "Refresh token not found."
        )

    result_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result_user.scalar_one_or_none()

    if not user:
        raise HTTPException(
            404, "User not found."
        )

    access_token_str = jwt_manager.create_access_token(
        data={"user_id": user.id},
    )

    return {
        "access_token": access_token_str,
    }
