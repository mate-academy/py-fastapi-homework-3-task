from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from pydantic.v1 import validator

from database.validators.accounts import validate_email, validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @validator("email")
    def validate_email(cls, email: str) -> str:
        return validate_email(email)

    @validator("password")
    def validate_password(cls, password: str) -> str:
        return validate_password_strength(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class TokenSchema(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str

    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
