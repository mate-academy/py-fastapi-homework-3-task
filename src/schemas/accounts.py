import re

from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")

        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "Password must contain at least one uppercase letter.")

        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lower letter.")

        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one digit.")

        if not re.search(r"[@$!%*?&#]", value):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )

        return value


class PasswordChangingRequestScheme(UserRegistrationRequestSchema):
    token: str


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class AccountActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class TokenVerificationSchema(BaseModel):
    token: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str
