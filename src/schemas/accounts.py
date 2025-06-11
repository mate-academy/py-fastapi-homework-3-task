from pydantic import BaseModel, EmailStr, field_validator
import re


# --- Registration ---
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", value):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


# --- Activation ---
class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


# --- Password Reset ---
class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", value):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return value


# --- Login ---
class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokensResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# --- Refresh ---
class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str


# --- Common Message Response ---
class MessageResponseSchema(BaseModel):
    message: str
