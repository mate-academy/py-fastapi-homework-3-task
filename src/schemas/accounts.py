from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from src.database import accounts_validators


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr

    @field_validator("email")
    def validate_email(cls, value: EmailStr):
        accounts_validators.validate_email(value)
        return value


class UserRegistrationRequestSchema(UserBase):
    model_config = ConfigDict(from_attributes=True)

    password: str

    @field_validator("password")
    def validate_password_reliability(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int


class UserActivationRequestSchema(UserBase):
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password")
    def validate_password_reliability(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def validate_password_reliability(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
