from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.user_crud import (
    create_user,
    get_user_by_email,
    activate_user,
    reset_request_user_password,
    reset_completion_user_password,
    create_user_access_and_refresh_tokens,
    create_new_user_access_token
)
from database import get_db

from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    new_user = await create_user(user_data=user_data, db=db)
    return new_user


@router.post("/activate/", status_code=200, response_model=MessageResponseSchema)
async def activate_account(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=activation_data.email, db=db)
    if not db_user:
        raise HTTPException(
            status_code=400,
            detail=f"A user with this email {activation_data.email} not found."
        )

    return await activate_user(
        user=db_user,
        activation_token=activation_data.token,
        db=db
    )


@router.post("/password-reset/request/", status_code=200, response_model=MessageResponseSchema)
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)

    return await reset_request_user_password(user=db_user, db=db)


@router.post("/reset-password/complete/", status_code=200, response_model=MessageResponseSchema)
async def password_reset_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(email=user_data.email, db=db)
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    return await reset_completion_user_password(
        user=db_user,
        new_password=user_data.password,
        token=user_data.token,
        db=db
    )


@router.post("/login/", status_code=201, response_model=UserLoginResponseSchema)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await get_user_by_email(email=login_data.email, db=db)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    return await create_user_access_and_refresh_tokens(
        user=db_user,
        login_password=login_data.password,
        db=db,
        jwt_manager=jwt_manager,
        settings=settings
    )


@router.post("/refresh/", status_code=200, response_model=TokenRefreshResponseSchema)
async def refresh_user_access_token(
        refresh_token_request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    return await create_new_user_access_token(
        refresh_token=refresh_token_request_data.refresh_token,
        db=db,
        jwt_manager=jwt_manager,
    )
