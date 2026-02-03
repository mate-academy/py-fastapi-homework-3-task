import re

from pydantic import BaseModel, EmailStr, field_validator, ConfigDict


def validate_password_complexity(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must contain at least 8 characters.")
    if not any(char.isupper() for char in v):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(char.isdigit() for char in v):
        raise ValueError("Password must contain at least one digit.")
    if not any(char.islower() for char in v):
        raise ValueError("Password must contain at least one lower letter.")
    if not re.search(r"[@$!%*?#&]", v):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
    return v


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class UserResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    pass


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteSchema(UserBase):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str


class TokenRefreshResponseSchema(BaseModel):
    pass
