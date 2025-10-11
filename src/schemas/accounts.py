import re

from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password : str = Field(min_length=8)


class UserLoginRequestSchema(UserBase):
    password: str = Field(min_length=8)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
