from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegister(BaseModel):
    email: str
    password: str


class UserRegisterResponse(BaseModel):
    id: int
    email: EmailStr


class UserActivate(BaseModel):
    email: EmailStr
    token: str


class UserResetPassword(BaseModel):
    email: EmailStr


class UserResetPasswordComplete(UserActivate):
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshAccessTokenResponse(BaseModel):
    access_token: str

class RefreshAccessTokenRequest(BaseModel):
    refresh_token: str