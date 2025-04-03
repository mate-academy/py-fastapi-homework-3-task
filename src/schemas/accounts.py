from pydantic import BaseModel, EmailStr, field_validator
from database import accounts_validators


# Write your code here
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @classmethod
    @field_validator("password", mode="before")
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr
    model_config = {
        "from_attribute": True
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    ...


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
    token_type: str = "bearer"

    model_config = {
        "from_attribute": True
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "from_attribute": True
    }
