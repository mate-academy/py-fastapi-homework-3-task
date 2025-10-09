from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class MessageResponseSchema(BaseModel):
    message: str

    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = ConfigDict(from_attributes=True)
