from pydantic import BaseModel, EmailStr, field_validator
from database import accounts_validators


class BaseAuthUserSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(BaseAuthUserSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserLoginRequestSchema(BaseAuthUserSchema):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str


class PasswordResetCompleteRequestSchema(BaseAuthUserSchema):
    token: str
