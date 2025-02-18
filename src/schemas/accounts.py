from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str
    group_id: int = 1

    model_config = ConfigDict(from_attributes=True)


class UserRegistrationResponseSchema(UserBase):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class ActivationTokenSchema(BaseModel):
    user_id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str
    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str
    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr
    model_config = ConfigDict(from_attributes=True)


class TokenResetSchema(BaseModel):
    token: str
    model_config = ConfigDict(from_attributes=True)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = ConfigDict(from_attributes=True)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
    model_config = ConfigDict(from_attributes=True)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    model_config = ConfigDict(from_attributes=True)
