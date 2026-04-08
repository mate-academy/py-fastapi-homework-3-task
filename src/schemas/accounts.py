from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Mapped

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema:
    email: EmailStr


class PasswordResetCompleteRequestSchema:
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema:
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema:
    email: EmailStr
    password: str


class TokenRefreshRequestSchema: ...


class TokenRefreshResponseSchema: ...
