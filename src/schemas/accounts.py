from pydantic import (
    BaseModel,
    EmailStr,
    field_validator,
    validator,
    ValidationError,
    root_validator,
)
import re
from database import accounts_validators


class UserCreate(BaseModel):
    email: EmailStr
    password: str

    @root_validator(pre=True)
    @classmethod
    def validate_password(cls, values):
        password = values.get("password")
        errors = []

        if len(password) < 8:
            errors.append("Password must contain at least 8 characters.")

        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit.")

        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")

        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lower letter.")

        if not re.search(r"[@$!%*?#&]", password):
            errors.append(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )

        if errors:
            raise ValueError(" | ".join(errors))

        return values


class UserResponse(BaseModel):
    id: int
    email: EmailStr


class UserActivate(BaseModel):
    email: EmailStr
    token: str


class UserLogin(UserCreate):
    pass


class UserLoginSuccess(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetComplete(BaseModel):
    email: EmailStr
    token: str
    password: str


class RefreshToken(BaseModel):
    refresh_token: str


class AccessToken(BaseModel):
    access_token: str
