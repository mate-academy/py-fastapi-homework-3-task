from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr, field_validator
import re


def _validate_password_common(v: str) -> str:
    # Порядок повідомлень ПОВИНЕН збігатися з тестами:
    # 1) довжина, 2) наявність великої (UPPERCASE), 3) наявність малої, 4) цифра, 5) спецсимвол
    if len(v) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lower letter.")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[@$!%*?#&]", v):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
    return v


# === Requests ===

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_common(v)


class ActivateAccountRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_common(v)


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class RefreshRequestSchema(BaseModel):
    refresh_token: str


# === Responses ===

class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")


class RefreshResponseSchema(BaseModel):
    access_token: str


class MessageResponse(BaseModel):
    message: str
