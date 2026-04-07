from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Mapped

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    group_id: int


class UserRegistrationResponseSchema(BaseModel):
    id: str
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema: ...


class MessageResponseSchema: ...


class PasswordResetRequestSchema: ...


class PasswordResetCompleteRequestSchema: ...


class UserLoginResponseSchema: ...


class UserLoginRequestSchema: ...


class TokenRefreshRequestSchema: ...


class TokenRefreshResponseSchema: ...
