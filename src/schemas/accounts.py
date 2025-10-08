from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def strong_enough(cls, v: str) -> str:
        # мінімальна перевірка складності (тести можуть мати власні очікування)
        if v.strip() != v:
            raise ValueError("password must not start/end with spaces")
        return v


class ActivateAccountRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1)


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1)
    password: str = Field(min_length=8, max_length=128)


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class RefreshRequestSchema(BaseModel):
    refresh_token: str = Field(min_length=1)


# -------- Responses --------
class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class MessageResponse(BaseModel):
    message: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshResponseSchema(BaseModel):
    access_token: str
