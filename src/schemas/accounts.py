from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)

    @classmethod
    @field_validator("password")
    def validate_password(cls, password):
        return accounts_validators.validate_password_strength(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    password: str
    token: str

    @classmethod
    @field_validator("email")
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)

    @classmethod
    @field_validator("password")
    def validate_password(cls, password):
        return accounts_validators.validate_password_strength(password)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
