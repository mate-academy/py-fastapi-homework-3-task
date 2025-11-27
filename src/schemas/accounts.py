from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


# Registration schemas
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = {
        "from_attributes": True
    }


# Activation schemas
class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserActivationResponseSchema(BaseModel):
    message: str


# Password reset request schemas
class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetRequestResponseSchema(BaseModel):
    message: str


# Password reset complete schemas
class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return accounts_validators.validate_password_strength(v)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str


# Login schemas
class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Refresh token schemas
class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class RefreshTokenResponseSchema(BaseModel):
    access_token: str
