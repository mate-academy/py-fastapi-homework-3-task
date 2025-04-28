import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

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
from exceptions import InvalidTokenError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from starlette.responses import JSONResponse

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetTokenRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post("/register/")
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:

    existing_user = await db.execute(
        select(UserModel)
        .filter_by(email=user_data.email)
    )
    if existing_user.scalar():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} "
                   f"already exists.",
        )

    group = await db.scalar(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not group:
        raise HTTPException(
            status_code=500,
            detail="User group not found in the database"
        )

    try:
        db_user = UserModel(
            email=user_data.email,
            password=user_data.password,
            group=group,
            activation_token=ActivationTokenModel(),
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )

    response_data = UserRegistrationResponseSchema(
        id=db_user.id,
        email=db_user.email
    ).dict()
    return JSONResponse(content=response_data, status_code=201)


@router.post("/activate/")
async def account_activation(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    existing_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .filter_by(email=user_data.email)
    )
    db_user = existing_user.scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=409,
            detail="User was not created in the database."
        )

    if (
        not db_user.activation_token
        or db_user.activation_token.token != user_data.token
        or db_user.activation_token.expires_at < datetime.now()
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active is True:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    db_user.is_active = True
    db_user.activation_token = None
    await db.commit()
    await db.refresh(db_user)

    response_data = MessageResponseSchema(
        message="User account activated successfully."
    ).dict()

    return JSONResponse(response_data, status_code=200)


@router.post("/password-reset/request/")
async def password_reset_token_request(
    user_data: PasswordResetTokenRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:

    existing_user = await db.execute(
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token),
            joinedload(UserModel.password_reset_token),
            joinedload(UserModel.refresh_tokens),
        )
        .filter(
            UserModel.email == user_data.email,
            UserModel.is_active.is_(True))
    )
    db_user = existing_user.unique().scalar_one_or_none()
    if not db_user:
        response_data = MessageResponseSchema(
            message="If you are registered, "
                    "you will receive an email with instructions."
        ).dict()
        return JSONResponse(response_data, status_code=200)

    if db_user.activation_token:
        await db.delete(db_user.activation_token)

    if db_user.password_reset_token:
        await db.delete(db_user.password_reset_token)

    for token in db_user.refresh_tokens:
        await db.delete(token)

    new_token = PasswordResetTokenModel(user_id=db_user.id)
    db.add(new_token)
    await db.commit()
    await db.refresh(db_user)

    response_data = MessageResponseSchema(
        message="If you are registered, "
                "you will receive an email with instructions."
    ).dict()
    return JSONResponse(response_data, status_code=200)


@router.post("/reset-password/complete/")
async def password_reset_completion_endpoint(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> JSONResponse:

    existing_user = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .filter(UserModel.email == user_data.email)
    )
    db_user = existing_user.unique().scalar_one_or_none()
    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    if db_user.is_active is not True:
        raise HTTPException(
            status_code=400,
            detail="User account is not active."
        )

    if db_user.password_reset_token.token != user_data.token:
        await db.delete(db_user.password_reset_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    if db_user.password_reset_token.expires_at < datetime.now():
        await db.delete(db_user.password_reset_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    try:
        db_user.password = user_data.password
        await db.flush()
        await db.delete(db_user.password_reset_token)
        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    response_data = MessageResponseSchema(
        message="Password reset successfully.").dict()
    return JSONResponse(response_data, status_code=200)


@router.post("/login/")
async def user_login_endpoint(
    user_data: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    existing_user = await db.execute(
        select(UserModel)
        .filter_by(email=user_data.email)
    )
    db_user = existing_user.scalar_one_or_none()
    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.")

    if db_user.is_active is False:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        access_token = (
            jwt_manager.create_access_token({"user_id": db_user.id}))
        refresh_token = (
            jwt_manager.create_refresh_token({"user_id": db_user.id}))

        refresh_token_model = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=os.getenv("REFRESH_TOKEN_DAYS_VALID", 1),
            token=refresh_token,
        )

        db.add(refresh_token_model)

        await db.flush()
        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    response_data = UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    ).dict()
    return JSONResponse(response_data, status_code=201)


@router.post("/refresh/")
async def access_token_refresh_endpoint(
    user_data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:

    try:
        payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
        user_id = payload["user_id"]

    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    existing_token = await db.execute(
        select(RefreshTokenModel).filter(
            RefreshTokenModel.token == user_data.refresh_token
        )
    )
    token_db = existing_token.scalar()
    if not token_db:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    existing_user = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.refresh_tokens))
        .filter(UserModel.id == user_id)
    )
    user_db = existing_user.scalar()
    if not user_db:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    response_data = TokenRefreshResponseSchema(
        access_token=access_token,
    ).dict()
    return JSONResponse(response_data, status_code=200)
