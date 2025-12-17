from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from pydantic import BaseModel, EmailStr, Field


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password_strength(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    detail: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    new_password: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    new_password: str

    @field_validator("new_password")
    def validate_password_strength(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    email: EmailStr


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password_strength(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PasswordResetSchema(BaseModel):
    email: EmailStr
    token: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
