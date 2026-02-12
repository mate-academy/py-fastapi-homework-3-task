from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not any(ch.isupper() for ch in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(ch.islower() for ch in v):
            raise ValueError("Password must contain at least one lower letter.")
        if not any(ch.isdigit() for ch in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(ch in "@$!%*?#&" for ch in v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., min_length=8, max_length=128)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
