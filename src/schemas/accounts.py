from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class BaseSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {"from_attributes": True}

    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator("password")
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(BaseSchema):
    pass


class UserRegistrationResponseSchema(BaseSchema):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {"from_attributes": True}


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class PasswordResetResponseSchema(BaseSchema):
    email: EmailStr
    reset_token: str
    password: str


class PasswordResetCompleteRequestSchema(BaseSchema):
    email: EmailStr
    token: str
    password: str


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {"from_attributes": True}


class UserLoginRequestSchema(BaseSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    token: str
    refresh_token: str
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
