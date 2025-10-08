from __future__ import annotations

from pydantic import BaseModel, EmailStr, field_validator


# ---------- Common ----------
class MessageResponse(BaseModel):
    message: str


# ---------- Register ----------
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    # НЕ ставимо Field(min_length=8), щоб віддати наше кастомне повідомлення, а не стандартне Pydantic
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        # Порядок перевірок має значення для тестів:
        # 1) довжина
        # 2) наявність великої літери
        # 3) наявність малої літери
        # 4) наявність цифри
        # 5) наявність спецсимвола
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lower letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?#&" for c in v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


# ---------- Activation ----------
class ActivateAccountRequestSchema(BaseModel):
    email: EmailStr
    token: str


# ---------- Password reset ----------
class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    # Аналогічно — без Field(min_length=8), щоб повернути наше повідомлення
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lower letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(c in "@$!%*?#&" for c in v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


# ---------- Login ----------
class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ---------- Refresh ----------
class RefreshRequestSchema(BaseModel):
    refresh_token: str


class RefreshResponseSchema(BaseModel):
    access_token: str
