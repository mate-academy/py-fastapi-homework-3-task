from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from database import get_db
from routes import crud
from schemas import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

SessionDep = Annotated[AsyncSession, Depends(get_db)]

JWTManager = Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)]


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(db: SessionDep, user: UserRegistrationRequestSchema):
    user = await crud.create_user(db=db, user=user)
    return user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(db: SessionDep, payload: UserActivationRequestSchema):

    await crud.activate_user(db=db, payload=payload)

    message = MessageResponseSchema(message="User account activated successfully.")
    return message


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(db: SessionDep, payload: PasswordResetRequestSchema):
    await crud.request_reset_token(db=db, payload=payload)
    message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )
    return message


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset(db: SessionDep, payload: PasswordResetCompleteRequestSchema):
    await crud.password_reset_complete(db=db, payload=payload)
    message = MessageResponseSchema(message="Password reset successfully.")
    return message


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    db: SessionDep, credentials: UserLoginRequestSchema, jwt_manager: JWTManager
):
    res_data = await crud.login_user(
        db=db, credentials=credentials, jwt_manager=jwt_manager
    )
    res = UserLoginResponseSchema(**res_data)
    return res


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def access_token_refresh(
    db: SessionDep, token: TokenRefreshRequestSchema, jwt_manager: JWTManager
):
    new_access_token = await crud.access_token_refresh(
        db=db, token=token, jwt_manager=jwt_manager
    )
    res = TokenRefreshResponseSchema(access_token=new_access_token)
    return res
