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
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    pass


class UserLoginResponseSchema(BaseModel):
    pass


class UserLoginRequestSchema(BaseModel):
    pass


class TokenRefreshRequestSchema(BaseModel):
    pass


class TokenRefreshResponseSchema(BaseModel):
    pass
