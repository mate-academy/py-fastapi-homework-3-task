from pydantic import BaseModel, EmailStr, field_validator

from database.validators.accounts import (
    validate_email,
    validate_password_strength
)


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    def email_validator(cls, value):
        return validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str
    group_id: int = 1

    @field_validator("password")
    def password_validator(cls, value):
        return validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    def email_validator(cls, value):
        return validate_email(value)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def password_validator(cls, value):
        return validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
