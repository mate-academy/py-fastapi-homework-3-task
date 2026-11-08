from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr

from database import accounts_validators


Email = Annotated[EmailStr, AfterValidator(str.lower)]
Password = Annotated[str, AfterValidator(accounts_validators.validate_password_strength)]


class UserRegistrationRequestSchema(BaseModel):
    email: Email
    password: Password


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: Email
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: Email


class PasswordResetCompleteRequestSchema(BaseModel):
    email: Email
    token: str
    password: Password


class UserLoginRequestSchema(BaseModel):
    email: Email
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
