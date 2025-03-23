<<<<<<< HEAD
from datetime import datetime, timezone, timedelta
import uuid

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
=======
import time
from datetime import datetime, timezone, timedelta
from typing import cast
import uuid
import re

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
>>>>>>> 55a94b6a8140ffcf615757bc75d38316d78c9424

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
<<<<<<< HEAD
from exceptions import TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from database.validators.accounts import validate_email, validate_password_strength
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.utils import generate_secure_token

=======
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from database.validators.accounts import validate_email, validate_password_strength
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

from schemas.accounts import UserRegistrationRequestSchema, UserRegistrationResponseSchema

from schemas.accounts import MessageResponseSchema

from schemas.accounts import UserActivationRequestSchema

from database.models.accounts import TokenBaseModel

from security.utils import generate_secure_token

from schemas.accounts import PasswordResetRequestSchema

from schemas.accounts import PasswordResetCompleteRequestSchema

from schemas.accounts import UserLoginResponseSchema

from schemas.accounts import UserLoginRequestSchema

from schemas.accounts import TokenRefreshResponseSchema, TokenRefreshRequestSchema
>>>>>>> 55a94b6a8140ffcf615757bc75d38316d78c9424

router = APIRouter()
SECRET_KEY = str(uuid.uuid4())


<<<<<<< HEAD
@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        user = result.scalar_one_or_none()
        if user:
            raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

        result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        user_group = result.scalar_one_or_none()

        if not user_group:
            raise HTTPException(status_code=500, detail="Default user group not found")

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        token = ActivationTokenModel(user_id=new_user.id)
        db.add(token)
        await db.commit()

        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    except Exception as e:
        print(e)
=======
# @router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
# def create_user(user: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
#     group_user = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
#     existing_email = db.query(UserModel).filter(UserModel.email == str(user.email)).first()
#     email_validated = validate_email(user.email)
#     password_validate = hash_password(validate_password_strength(user.password))
#     if existing_email:
#         raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
#     try:
#         new_user = UserModel(email=email_validated, _hashed_password=password_validate, group_id=group_user.id)
#         db.add(new_user)
#         db.commit()
#         db.refresh(new_user)
#
#         jwt = JWTAuthManager(
#             secret_key_access=str(uuid.uuid4()),
#             secret_key_refresh=str(uuid.uuid4()),
#             algorithm="HS256"
#         )
#         activation_token = jwt._create_token(
#             data={"exp": new_user},
#             secret_key=SECRET_KEY,
#             expires_delta=timedelta(days=10)
#         )
#         return {"id": new_user.id, "email": new_user.email, "activation_token": activation_token}
#     except Exception:
#         db.rollback()
#         raise HTTPException(status_code=500, detail="An error occurred during user creation.")
#     finally:
#         db.close()

@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
def create_user(user: UserRegistrationRequestSchema, db: Session = Depends(get_db)):
    group_user = db.query(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER).first()
    existing_email = db.query(UserModel).filter(UserModel.email == str(user.email)).first()
    email_validated = validate_email(user.email)
    if existing_email:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    try:
        password_validate = hash_password(user.password)
        new_user = UserModel(
            email=email_validated,
            _hashed_password=password_validate,
            group_id=group_user.id,
        )
        db.add(new_user)
        db.commit()

        create_token = ActivationTokenModel(
            user_id=new_user.id,
            token=generate_secure_token(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=2)
        )
        db.add(create_token)
        db.commit()

        new_user.activation_token = create_token

        db.commit()
        db.refresh(new_user)
        print(create_token)
        return {"id": new_user.id, "email": new_user.email, "activation_token": new_user.activation_token.token}
    except Exception as e:
        db.rollback()
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
    finally:
        db.close()
>>>>>>> 55a94b6a8140ffcf615757bc75d38316d78c9424


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
def activate_user(schema: UserActivationRequestSchema, db: Session = Depends(get_db)):

    user = db.query(UserModel).filter(UserModel.email == str(schema.email)).first()
    is_expired = db.query(ActivationTokenModel).filter(ActivationTokenModel.token == str(schema.token)).first()

    if not is_expired:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if not user:
        raise HTTPException(status_code=400, detail="User with this email does not exist.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if is_expired.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    user.is_active = True
    db.delete(user.activation_token)
    db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=200)
def password_reset_request(request: PasswordResetRequestSchema, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == str(request.email)).one_or_none()

    if user and user.is_active:
        db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
        db.commit()

        new_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_token)
        db.commit()
        print(new_token)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=200)
def password_reset_complete(request: PasswordResetCompleteRequestSchema, db: Session = Depends(get_db)):
    current_time = datetime.now(timezone.utc)
    user = db.query(UserModel).filter(UserModel.email == str(request.email)).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:

        password_reset = db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).first()
        if not password_reset:
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if password_reset.expires_at.replace(tzinfo=timezone.utc) < current_time:
            db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
            db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if password_reset.token != request.token:
            db.query(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id).delete()
            db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if (
                user
                and password_reset.token == request.token
                and password_reset.expires_at.replace(tzinfo=timezone.utc) >= current_time
        ):
            user._hashed_password = hash_password(validate_password_strength(request.password))
            db.commit()
            return {"message": "Password reset successfully."}
        else:
            db.rollback()
            raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
def login(
        request: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = db.query(UserModel).filter(UserModel.email == str(request.email)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.verify_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        if user.email == request.email and user.verify_password(request.password):
            access_token = jwt_manager.create_access_token(
                data={"sub": user.email, "user_id": user.id},
            )

            refresh_token = jwt_manager.create_refresh_token(
                data={"sub": user.email, "user_id": user.id},
            )
            create_refresh_token = RefreshTokenModel.create(
                user_id=user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token
            )
            db.add(create_refresh_token)
            db.commit()
            db.refresh(create_refresh_token)

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer"
            }

        else:
            raise HTTPException(status_code=500, detail="An error occurred while processing the request.")
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
def access_token_refresh(
        request: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    refresh = db.query(RefreshTokenModel).filter(RefreshTokenModel.token == str(request.refresh_token)).first()

    try:
        jwt_manager.decode_refresh_token(request.refresh_token)
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    if not refresh:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    jwt_obj = jwt_manager.decode_refresh_token(refresh.token)

    if not jwt_obj or "sub" not in jwt_obj:
        raise HTTPException(status_code=404, detail="User not found.")

    user = db.query(UserModel).filter(UserModel.email == jwt_obj["sub"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        new_access_token = jwt_manager.create_access_token(
            data={"sub": user.email, "user_id": user.id}
        )
        return {"access_token": new_access_token}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
