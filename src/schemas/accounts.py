from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email", mode="after")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password", mode="after")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
