from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from database import accounts_validators


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


# ---------------------------------------------------------------------------
# Generic message response (activation, password-reset request/complete)
# ---------------------------------------------------------------------------

class MessageResponseSchema(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Account activation
# ---------------------------------------------------------------------------

class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
