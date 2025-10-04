from datetime import date
import re
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator, Field, validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr = Field(description="Valid email address")


class PasswordValidator(BaseModel):
    password: str

    @validator("password")
    def validate_password_strength(cls, value):
        errors = []

        if len(value) < 8:
            errors.append("Password must contain at least 8 characters.")
        if not re.search(r"\d", value):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[A-Z]", value):
            errors.append(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[a-z]", value):
            errors.append("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", value):
            errors.append(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )

        if errors:
            raise ValueError(" | ".join(errors))

        return value


class CreateUser(PasswordValidator, UserBase):
    pass


class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True


class TokenBase(BaseModel):
    token: str


class TokenCreate(TokenBase):
    expires_at: date
    user_id: int


class TokenActivate(UserBase):
    token: str


class TokenPasswordRefresh(UserBase):
    pass


class ResetPassword(PasswordValidator, TokenBase, UserBase):
    pass


class LoginSchema(PasswordValidator, UserBase):
    pass


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefresh(BaseModel):
    refresh_token: str
