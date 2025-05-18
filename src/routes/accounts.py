from datetime import timezone
from starlette.status import HTTP_201_CREATED
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import JSONResponse

from config import get_jwt_auth_manager
from database import (
    UserModel,
    RefreshTokenModel,
)
from routes.security import ACCESS_TOKEN_EXPIRE_MINUTES
from schemas.accounts import (
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema
)
from crud import (
    create_user,
    get_user_by_email,
    activate_token,
    password_reset,
    password_reset_complete
)
from database import get_db
from security.passwords import verify_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        db_user = await get_user_by_email(db, user.email)
        if db_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user.email} already exists."
            )
        result = await create_user(db, user)
        return UserRegistrationResponseSchema(**result)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/")
async def activate_user(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):

    try:
        token_result = await activate_token(
            activation_token=user_data.token,
            email=user_data.email,
            db=db
        )

        if token_result == "already_active":
            return JSONResponse(
                status_code=400,
                content={"detail": "User account is already active."}
            )
        elif token_result == "invalid_token":
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid or expired activation token."}
            )
        elif token_result is True:
            return JSONResponse(
                status_code=200,
                content={"message": "User account activated successfully."}
            )

        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid or expired activation token."}
        )

    except Exception as e:
        print(f"[activate_user] Помилка: {str(e)}")
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid or expired activation token."}
        )


@router.post("/password-reset/request/")
async def reset_password(request_body: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    await password_reset(email=request_body.email, db=db)
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
async def reset_password_complete(
        request_body: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    await password_reset_complete(
        email=request_body.email,
        token=request_body.token,
        password=request_body.password,
        db=db
    )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        login_data: UserLoginRequestSchema,
        # email: str,
        # password: str,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        email = login_data.email
        password = login_data.password
        db_user = await get_user_by_email(db, email)
        if not db_user or not verify_password(password, db_user._hashed_password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if not db_user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = jwt_manager.create_access_token(
            {"sub": db_user.email, "user_id": db_user.id}, expires_delta=access_token_expires
        )
        refresh_token = jwt_manager.create_refresh_token({"sub": str(db_user.id), "user_id": db_user.id})
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        db_token = RefreshTokenModel(
            token=refresh_token,
            user_id=db_user.id,
            expires_at=expires_at
        )
        db.add(db_token)
        await db.commit()
        return JSONResponse(
            status_code=HTTP_201_CREATED,
            content={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            }
        )
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh(
        body: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        try:
            jwt_manager.decode_refresh_token(body.refresh_token)
        except Exception as e:
            print(f"Error decoding refresh token: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )

        token_query = select(RefreshTokenModel).where(RefreshTokenModel.token == body.refresh_token)
        token_result = await db.execute(token_query)
        db_refresh_token = token_result.scalar_one_or_none()

        if not db_refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

        # Ensure both datetimes have timezone information
        expires_at = db_refresh_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")

        user_query = select(UserModel).where(UserModel.id == db_refresh_token.user_id)
        user_result = await db.execute(user_query)
        user = user_result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        new_access_token = jwt_manager.create_access_token({"sub": str(user.id), "user_id": user.id})

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"access_token": new_access_token}
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in refresh endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail="Помилка при оновленні токену"
        )
