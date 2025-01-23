from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class BaseSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {"from_attributes": True}

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class ActivationTokenSchema(BaseModel):
    token: str


class UserRegistrationRequestSchema(BaseSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr
    activation_token: ActivationTokenSchema

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class PasswordResetCompleteRequestSchema(BaseSchema):
    email: EmailStr
    token: str
    password: str


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginRequestSchema(BaseSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
