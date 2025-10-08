from __future__ import annotations

from pydantic import BaseModel, EmailStr, field_validator


# ---------- Common ----------

class MessageResponse(BaseModel):
    message: str


# ---------- Registration ----------

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str  # use custom validator to control exact error texts

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        specials = "@$!%*?#&"
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not any(ch.isdigit() for ch in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(ch.isupper() for ch in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(ch.islower() for ch in v):
            raise ValueError("Password must contain at least one lower letter.")
        if not any(ch in specials for ch in v):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
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
    password: str



class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequestSchema(BaseModel):
    refresh_token: str


class RefreshResponseSchema(BaseModel):
    access_token: str
