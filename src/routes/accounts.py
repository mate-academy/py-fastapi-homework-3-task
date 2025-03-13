from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager
from crud.user import UserDB
from database import (
    get_db,
    UserModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


# Write your code here
@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        user = await UserDB.register_user(db, user)
        return {
            "id": user.id,
            "email": user.email,
        }
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
)
async def activate(
    data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        await UserDB.activate_user_account(data, db)
        return {"message": "User account activated successfully."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
)
async def password_reset_request(
    data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        await UserDB.password_reset_request(data, db)
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    except ValueError as e:
        return {"message": str(e)}


@router.post("/reset-password/complete/")
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    await UserDB.user_password_reset_complete(data, db)

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await UserDB.login_user(data, db)

    return result


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        token_data = jwt_manager.decode_refresh_token(data.refresh_token)
        print(token_data)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token is invalid.")

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    )
    result = await db.execute(stmt)
    refresh_token_record = result.scalar_one_or_none()
    if not refresh_token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = token_data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    try:
        user_id = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:

        return JSONResponse(status_code=404, content={"detail": "User not found."})

    new_access_token = jwt_manager.create_access_token(data={"user_id": user_id})

    return {"access_token": new_access_token}
