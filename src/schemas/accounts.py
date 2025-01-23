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

    model_config = {
        "from_attributes": True
    }


class UserLoginRequestSchema(BaseAuthUserSchema):
    pass


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class PasswordResetCompleteRequestSchema(BaseAuthUserSchema):
    token: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
