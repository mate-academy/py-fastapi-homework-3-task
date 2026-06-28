from pydantic import BaseModel, field_validator, ConfigDict
from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_user_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_user_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
