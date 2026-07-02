from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import get_db, get_settings, get_jwt_auth_manager
from database.models.accounts import (
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupModel,
)
from database.validators.accounts import UserGroupEnum
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserLoginRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetConfirmSchema,
    TokenRefreshRequestSchema,
    UserResponseSchema,
)
from security.passwords import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


@router.post("/register/", response_model=UserResponseSchema, status_code=201)
async def register(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        "SELECT * FROM users WHERE email = :email",
        {"email": user_data.email},
    )
    existing = result.fetchone()
    if existing:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    user_group = await db.execute(
        "SELECT * FROM user_groups WHERE name = :name",
        {"name": UserGroupEnum.USER},
    )
    group = user_group.fetchone()

    try:
        user = UserModel(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            group_id=group.id,
            is_active=False,
        )
        db.add(user)
        await db.flush()

        token = ActivationTokenModel(user_id=user.id)
        db.add(token)

        await db.commit()
        await db.refresh(user)
        return user
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/")
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute("SELECT * FROM users WHERE email = :email", {"email": data.email})
    user = result.fetchone()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_res = await db.execute(
        "SELECT * FROM activation_tokens WHERE user_id = :user_id AND token = :token",
        {"user_id": user.id, "token": data.token},
    )
    token = token_res.fetchone()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    try:
        user.is_active = True
        await db.delete(token)
        await db.commit()
        return {"message": "User account activated successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during activation.")


@router.post("/password-reset/request/")
async def password_reset_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute("SELECT * FROM users WHERE email = :email", {"email": data.email})
    user = result.fetchone()

    if user and user.is_active:
        await db.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = :user_id",
            {"user_id": user.id},
        )
        token = PasswordResetTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def password_reset_complete(data: PasswordResetConfirmSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute("SELECT * FROM users WHERE email = :email", {"email": data.email})
    user = result.fetchone()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_res = await db.execute(
        "SELECT * FROM password_reset_tokens WHERE user_id = :user_id AND token = :token",
        {"user_id": user.id, "token": data.token},
    )
    token = token_res.fetchone()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.hashed_password = hash_password(data.password)
        await db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/")
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute("SELECT * FROM users WHERE email = :email", {"email": data.email})
    user = result.fetchone()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
        db_token = RefreshTokenModel(user_id=user.id, token=refresh_token)
        db.add(db_token)
        await db.commit()

        access_token = jwt_manager.create_access_token({"user_id": user.id})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/api/v1/accounts/refresh/")
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    result = await db.execute(
        "SELECT * FROM refresh_tokens WHERE token = :token",
        {"token": data.refresh_token},
    )
    token = result.fetchone()

    if not token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_res = await db.execute("SELECT * FROM users WHERE id = :id", {"id": payload["user_id"]})
    user = user_res.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": access_token}
