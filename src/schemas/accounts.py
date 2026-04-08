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


class UserActivationRequestSchema: ...


class MessageResponseSchema: ...


class PasswordResetRequestSchema: ...


class PasswordResetCompleteRequestSchema: ...


class UserLoginResponseSchema: ...


class UserLoginRequestSchema: ...


class TokenRefreshRequestSchema: ...


class TokenRefreshResponseSchema: ...
