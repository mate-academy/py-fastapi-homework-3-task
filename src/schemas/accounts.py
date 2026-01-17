from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators, UserGroupEnum


# Write your code here
class UserModel(BaseModel):
    email: EmailStr


class UserCreate(UserModel):
    password: str
    group: str = UserGroupEnum.USER


class UserRead(UserModel):
    id: int
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str


class ActivateRequest(BaseModel):
    email: str
    token: str


class ActivateResponse(BaseModel):
    message: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetResponse(BaseModel):
    message: str


class PasswordResetCompleteRequest(BaseModel):
    email: EmailStr
    token: str
    password: str


class PasswordResetCompleteResponse(BaseModel):
    message: str


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    message: str
