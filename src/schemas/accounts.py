from pydantic import BaseModel, EmailStr, validator, constr
from pydantic import ConfigDict
import re


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @validator("password")
    def field_validate_password(cls, v):
        errors = []
        if len(v) < 8:
            errors.append("Password must contain at least 8 characters.")
        if not re.search(r"\d", v):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[A-Z]", v):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            errors.append("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", v):
            errors.append("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")

        if errors:
            raise ValueError("; ".join(errors))
        return v

    model_config = ConfigDict(from_attributes=True)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str  # тоже без constr, своя валидация

    @validator("password")
    def field_validate_password(cls, v):
        errors = []
        if len(v) < 8:
            errors.append("Password must contain at least 8 characters.")
        if not re.search(r"\d", v):
            errors.append("Password must contain at least one digit.")
        if not re.search(r"[A-Z]", v):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            errors.append("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", v):
            errors.append("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")

        if errors:
            raise ValueError("; ".join(errors))
        return v

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
