from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(max_length=255)

    @field_validator("email")
    @classmethod
    def validate_email(cls, user_email):
        return accounts_validators.validate_email(user_email)

    @field_validator("password")
    @classmethod
    def validate_password(cls, raw_password):
        return accounts_validators.validate_password_strength(raw_password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, user_email):
        return accounts_validators.validate_email(user_email)


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, user_email):
        return accounts_validators.validate_email(user_email)

    @field_validator("password")
    @classmethod
    def validate_password(cls, raw_password):
        return accounts_validators.validate_password_strength(raw_password)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
