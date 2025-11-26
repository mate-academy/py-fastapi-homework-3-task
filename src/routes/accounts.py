from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from src.config.dependencies import get_jwt_auth_manager, get_settings
from src.config.settings import BaseAppSettings
from src.crud import (
    get_user_by_email,
    create_user,
    activate_user,
    reset_password_token,
    reset_password_completion,
    login_user,
    access_token_refresh
)
from src.database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError

from src.schemas.accounts import (
    UserRegisterRequestSchema,
    UserRegisterResponseSchema,
    UserActivation,
    PasswordResetToken,
    LoginRequestSchema,
    LoginRequestResponseSchema,
    PasswordResetCompletion,
    RefreshAccessResponseSchema, RefreshAccessRequestSchema
)
from src.security.interfaces import JWTAuthManagerInterface

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register/", response_model=UserRegisterResponseSchema)
async def register(user: UserRegisterRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    return await create_user(db, user)


@router.post("/activate/")
async def activate(data: UserActivation, db: AsyncSession = Depends(get_db)):
    return await activate_user(db, data)


@router.post("/password-reset/request/")
async def reset_password_request(data: PasswordResetToken, db: AsyncSession = Depends(get_db)):
    return await reset_password_token(db, data)


@router.post("/reset-password/complete/")
async def reset_password_complete(data: PasswordResetCompletion, db: AsyncSession = Depends(get_db)):
    return await reset_password_completion(db, data)


@router.post("/login/", response_model=LoginRequestResponseSchema)
async def login(db: AsyncSession,
                data: LoginRequestSchema,
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                settings: BaseAppSettings = Depends(get_settings)):
    return await login_user(db, data, jwt_manager, settings)


@router.post("/api/v1/accounts/refresh/", response_model=RefreshAccessResponseSchema)
async def refresh_access(db: AsyncSession,
                         data: RefreshAccessRequestSchema,
                         jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
                         ):
    return await access_token_refresh(db, data, jwt_manager)
