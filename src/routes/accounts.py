from sqlite3 import IntegrityError
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from crud.accounts import register_user, activate_user, password_reset, password_reset_complete, login_user, \
    refresh_access_token
from crud.exceptions import UserAlreadyExist, UserError, UserDoesNotExist, UserAlreadyActivated, \
    UserNotActivated, InvalidPassword
from database import (
    get_db,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    MessageResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, \
    UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED
)
async def create_user(
    db: Annotated[AsyncSession, Depends(get_db)], user_data: UserRegistrationRequestSchema
):
    try:
        return await register_user(db=db, user_data=user_data)
    except UserAlreadyExist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    except (UserError, SQLAlchemyError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/", status_code=status.HTTP_200_OK, response_model=MessageResponseSchema
)
async def activate_the_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: UserActivationRequestSchema
):
    try:
        await activate_user(db, user_data=user_data)
    except (UserDoesNotExist, TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    except UserAlreadyActivated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/", status_code=status.HTTP_200_OK, response_model=MessageResponseSchema
)
async def reset_user_password(
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: PasswordResetRequestSchema
):
    await password_reset(db, user_data=user_data)
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/", status_code=status.HTTP_200_OK, response_model=MessageResponseSchema
)
async def reset_user_password_complete(
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: PasswordResetCompleteRequestSchema
):
    try:
        await password_reset_complete(db, user_data=user_data)
        return MessageResponseSchema(message="Password reset successfully.")
    except (UserDoesNotExist, UserNotActivated, InvalidTokenError, TokenExpiredError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    except (IntegrityError, SQLAlchemyError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/", status_code=status.HTTP_201_CREATED, response_model=UserLoginResponseSchema
)
async def login_the_user(
    jwt_dep: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_data: UserLoginRequestSchema
):
    try:
        return await login_user(db=db, user_data=user_data, jwt=jwt_dep)

    except UserNotActivated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    except (UserDoesNotExist, InvalidPassword):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    except (IntegrityError, SQLAlchemyError):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/", status_code=status.HTTP_200_OK, response_model=TokenRefreshResponseSchema
)
async def access_token_refresh(
    jwt_dep: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
    db: Annotated[AsyncSession, Depends(get_db)],
    token: TokenRefreshRequestSchema
):
    try:
        return await refresh_access_token(db=db, token_data=token, jwt=jwt_dep)
    except UserDoesNotExist:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
