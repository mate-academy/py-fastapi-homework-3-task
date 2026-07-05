from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from database.models.accounts import UserGroupEnum


class UserSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str):
        return accounts_validators.validate_password_strength(password=value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr):
        return accounts_validators.validate_email(user_email=value)


class UserRegistrationRequestSchema(UserSchema):
    role: UserGroupEnum = UserGroupEnum.USER


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


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
