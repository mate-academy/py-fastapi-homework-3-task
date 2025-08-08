from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from database.models.accounts import UserGroupEnum



class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    role: UserGroupEnum = UserGroupEnum.USER


    @field_validator("password")
    @classmethod
    def password_strength_validator(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


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


    @field_validator("password")
    @classmethod
    def password_strength_validator(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
