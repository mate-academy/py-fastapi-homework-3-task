from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError
from schemas.accounts import (
    UserListModel,
    UserRegisterModel,
    UserActivateModel,
    UserBaseModel,
    UserPasswordResetModel,
    RefreshTokenRequestModel,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/", response_model=UserListModel, status_code=status.HTTP_201_CREATED
)
async def register(user_data: UserRegisterModel, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    user = result.scalar_one_or_none()

    if user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )

    group = result.scalar_one_or_none()

    try:
        new_user = UserModel.create(
            email=user_data.email, raw_password=user_data.password, group_id=group.id
        )

        db.add(new_user)

        activation_token = ActivationTokenModel(user=new_user)

        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    return new_user


@router.post("/activate/")
async def activate(current_user: UserActivateModel, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == current_user.token)
    )

    token = result.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if token.user.email != current_user.email:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if token.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token.user.is_active = True

    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def reset_password_token(
    current_user: UserBaseModel, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == current_user.email)
    )

    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user)
    )

    new_token = PasswordResetTokenModel(user=user)

    db.add(new_token)

    await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
async def reset_password(
    current_user: UserPasswordResetModel, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(PasswordResetTokenModel)
        .options(joinedload(PasswordResetTokenModel.user))
        .where(PasswordResetTokenModel.token == current_user.token)
    )

    token = result.scalar_one_or_none()

    if token is None:
        result = await db.execute(
            select(UserModel).where(UserModel.email == current_user.email)
        )
        user = result.scalar_one_or_none()

        if user:
            result = await db.execute(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            reset_token = result.scalar_one_or_none()

            if reset_token:
                await db.delete(reset_token)
                await db.commit()

        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if token.user.email != current_user.email:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if not token.user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()

        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        token.user.password = current_user.password

        await db.delete(token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
    current_user: UserRegisterModel,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == current_user.email)
    )

    user = result.scalar_one_or_none()

    if user is None or user.verify_password(current_user.password) is False:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    data = {"user_id": user.id}

    access_token = jwt_manager.create_access_token(data)
    refresh_token = jwt_manager.create_refresh_token(data)

    try:
        refresh_token_model = RefreshTokenModel.create(
            user_id=user.id, days_valid=7, token=refresh_token
        )

        db.add(refresh_token_model)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/")
async def refresh(
    current_token: RefreshTokenRequestModel,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        data = jwt_manager.decode_refresh_token(current_token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_id = data["user_id"]

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == current_token.refresh_token
        )
    )

    token = result.scalar_one_or_none()

    if token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))

    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if user_id != token.user_id:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data)

    return {"access_token": access_token}
