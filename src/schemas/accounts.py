from pydantic import BaseModel, EmailStr, field_validator, Field
import re

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @classmethod
    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[@$!%*?#&]", v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class MessageResponseSchema(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @classmethod
    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[@$!%*?#&]", v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserAccessTokenResponseSchema(BaseModel):
    access_token: str


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserRefreshToken(BaseModel):
    refresh_token: str


class UserAccessToken(BaseModel):
    access_token: str
