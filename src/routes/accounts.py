from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from database import get_db
from database.crud import users as users_crud
from database.crud.exceptions import UserAlreadyExistsError, UserException
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    try:
        new_user = await users_crud.create_user(session=db, user_data=user_data)
    except UserAlreadyExistsError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A user with this email {user_data.email} already exists.")
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A user with this email {user_data.email} already exists.")
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")
    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post("/activate/")
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    try:
        await users_crud.activate_user(session=db, email=data.email, token=data.token)
    except UserException as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"{e}")
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/")
async def reset_password_request(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    await users_crud.create_password_reset_token(session=db, email=data.email)
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/password-reset/complete/")
async def reset_password_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    try:
        await users_crud.complete_password_reset(session=db, data=data)
    except UserException:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid email or token.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")
    return MessageResponseSchema(message="Password reset successfully.")
