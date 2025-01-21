from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

class BaseAuthUserSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(BaseAuthUserSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = {
        "from_attributes": True
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseAuthUserSchema):
    token: str


class UserLoginRequestSchema(BaseAuthUserSchema):
    pass

class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
