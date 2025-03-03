from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone

from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from security.token_manager import create_access_token, create_refresh_token
from schemas.accounts import (
    RegisterUserSchema,
    ActivateUserSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    LoginSchema,
    TokenResponseSchema,
    RefreshTokenSchema
)

router = APIRouter()


@router.post("/register", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(register_data: RegisterUserSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == register_data.email))
    user_exist = result.scalars().first()

    if user_exist:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A user with this email {register_data.email} already exists.")

    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = result.scalars().first()

    new_user = UserModel(email=register_data.email, hashed_password=register_data.password, group_id=user_group.id)
    db.add(new_user)
    await db.commit()

    return new_user


@router.post("/activate", status_code=status.HTTP_200_OK)
async def activate_user(activation_data: ActivateUserSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == activation_data.token))
    token_record = result.scalars().first()

    if not token_record or token_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    result = await db.execute(select(UserModel).where(UserModel.email == activation_data.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found.")
    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    user.is_active = True
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request", status_code=status.HTTP_200_OK)
async def request_password_reset(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id).delete())

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/password-reset/complete", status_code=status.HTTP_200_OK)
async def reset_password(data: PasswordResetCompleteSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.token == data.token))
    token_record = result.scalars().first()

    if not token_record or token_record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset token.")

    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    user.hashed_password = data.password
    await db.commit()

    return {"message": "Password reset successfully."}


@router.post("/login", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK)
async def login_user(login_data: LoginSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == login_data.email))
    user = result.scalars().first()

    if not user or user.hashed_password != login_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    new_refresh_token = RefreshTokenModel(user_id=user.id, token=refresh_token)
    db.add(new_refresh_token)
    await db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(data: RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).where(UserModel.id == token_record.user_id))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = create_access_token(user.id)

    return {"access_token": new_access_token}
