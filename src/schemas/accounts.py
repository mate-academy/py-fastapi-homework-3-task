from typing import Annotated

from pydantic import BaseModel, EmailStr, AfterValidator, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: Annotated[EmailStr, AfterValidator(accounts_validators.validate_email)]
    password: Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


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
    password: Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


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
