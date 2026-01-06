from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from crud import create_user
from crud import activate_user_account, password_reset, reset_password_completion, \
    access_token_refresh, authenticate_user
from database import (
    get_db,
)
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, MessageResponseSchema, \
    PasswordResetRequestSchema, UserLoginResponseSchema, TokenRefreshResponseSchema, UserActivationRequestSchema, \
    PasswordResetCompleteRequestSchema, UserLoginRequestSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED, response_model=UserRegistrationResponseSchema)
async def register_user_endpoint(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    return await create_user(user_data=user_data, db=db)


@router.post("/activate/", status_code=200, response_model=MessageResponseSchema)
async def activate_user_endpoint(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    return await activate_user_account(db=db, user_data=user_data)


@router.post("/password-reset/request/", status_code=200, response_model=MessageResponseSchema)
async def reset_password_request_endpoint(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    return await password_reset(db=db, user_data=user_data)


@router.post("/reset-password/complete/", status_code=200, response_model=MessageResponseSchema)
async def reset_password_request_completion_endpoint(user_data: PasswordResetCompleteRequestSchema,
                                                     db: AsyncSession = Depends(get_db)
                                                     ):
    return await reset_password_completion(db=db, user_data=user_data)


@router.post("/login/", status_code=201, response_model=UserLoginResponseSchema)
async def login_endpoint(user_data: UserLoginRequestSchema,
                         db: AsyncSession = Depends(get_db),
                         jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
                         ):
    return await authenticate_user(db=db, user_data=user_data, jwt_manager=jwt_manager)


@router.post("/refresh/", status_code=200, response_model=TokenRefreshResponseSchema)
async def access_token_refresh_endpoint(user_data: TokenRefreshRequestSchema,
                                        db: AsyncSession = Depends(get_db),
                                        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
                                        ):
    return await access_token_refresh(db=db, user_data=user_data, jwt_manager=jwt_manager)
