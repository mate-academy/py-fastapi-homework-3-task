from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class BaseUserSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(BaseUserSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    message: str


class PasswordResetRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseUserSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
