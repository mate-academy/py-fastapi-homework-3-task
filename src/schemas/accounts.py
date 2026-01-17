from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator

from database.validators.accounts import validate_email, validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @field_validator("email")
    def validate_email_field(cls, v):
        return validate_email(v)

    @field_validator("password")
    def validate_password_field(cls, v):
        return validate_password_strength(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


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
    password: str

    @field_validator("password")
    def validate_password_field(cls, v):
        return validate_password_strength(v)


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
    token_type: str = "bearer"
