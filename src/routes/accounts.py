from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
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
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        if await db.scalar(select(UserModel).where(UserModel.email == user_data.email)):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        if (
            user_group_id := await db.scalar(
                select(UserGroupModel.id).where(
                    UserGroupModel.name == UserGroupEnum.USER
                )
            )
        ) is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found. Application misconfigured.",
            )

        new_user = UserModel(email=user_data.email, group_id=user_group_id)
        new_user.password = user_data.password

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)

    except HTTPException as e:
        await db.rollback()
        raise e
    except ValueError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        ) from e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == activation_data.email)
            .options(joinedload(UserModel.activation_token))
        )

        if (
            not user
            or not user.activation_token
            or user.activation_token.token != activation_data.token
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        expires_at = cast(datetime, user.activation_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            await db.delete(user.activation_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True
        await db.delete(user.activation_token)
        await db.commit()
        await db.refresh(user)

        return MessageResponseSchema(message="User account activated successfully.")

    except HTTPException as e:
        await db.rollback()
        raise e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    reset_request_data: PasswordResetRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == reset_request_data.email)
            .options(joinedload(UserModel.password_reset_token))
        )

        if user and user.is_active:
            try:
                if user.password_reset_token:
                    await db.delete(user.password_reset_token)
                    await db.flush()

                new_reset_token = PasswordResetTokenModel(user_id=user.id)
                db.add(new_reset_token)
                await db.commit()
            except SQLAlchemyError as e:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred while creating password reset token.",
                ) from e
            except Exception as e:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An unexpected error occurred during password reset token creation.",
                ) from e

    except HTTPException as e:
        await db.rollback()
        raise e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing password reset request.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing password reset request.",
        ) from e

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    reset_complete_data: PasswordResetCompleteRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == reset_complete_data.email)
            .options(joinedload(UserModel.password_reset_token))
        )

        if (
            not user
            or not user.password_reset_token
            or user.password_reset_token.token != reset_complete_data.token
        ):
            if user and user.password_reset_token:
                await db.delete(user.password_reset_token)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        expires_at = cast(datetime, user.password_reset_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        if datetime.now(timezone.utc) > expires_at:
            await db.delete(user.password_reset_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = reset_complete_data.password
        await db.delete(user.password_reset_token)
        await db.commit()
        await db.refresh(user)

        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException as e:
        await db.rollback()
        raise e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def user_login(
    login_data: UserLoginRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[BaseAppSettings, Depends(get_settings)],
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == login_data.email)
        )

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token = jwt_manager.create_access_token(data={"user_id": user.id})
        refresh_token_str = jwt_manager.create_refresh_token(data={"user_id": user.id})

        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str,
        )
        db.add(refresh_token_obj)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )

    except HTTPException as e:
        await db.rollback()
        raise e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    refresh_request_data: TokenRefreshRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        try:
            payload = jwt_manager.decode_refresh_token(
                refresh_request_data.refresh_token
            )
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token."
            )

        user_id = payload.get("sub") or payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid refresh token payload.",
            )

        refresh_token_obj = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.token == refresh_request_data.refresh_token,
            )
        )
        if not refresh_token_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except HTTPException as e:
        await db.rollback()
        raise e
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from e
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred.",
        ) from e
