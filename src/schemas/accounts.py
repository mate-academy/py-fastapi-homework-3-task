from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators, UserGroupEnum


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    group: UserGroupEnum = UserGroupEnum.USER

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, user_email: str) -> str:
        return accounts_validators.validate_email(user_email)

    @field_validator("password")
    @classmethod
    def validate_user_password_strength(cls, user_password: str) -> str:
        return accounts_validators.validate_password_strength(user_password)


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(PasswordResetRequestSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_user_password_strength(cls, user_password: str) -> str:
        return accounts_validators.validate_password_strength(user_password)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
