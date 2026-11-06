from pydantic import BaseModel, EmailStr, ConfigDict, field_validator

from database import accounts_validators, UserGroupModel


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserCreateSchema(UserBase):
    password: str
    group_id: int


class UserReadSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class AccountActivationRequestSchema(UserBase):
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteSchema(UserBase):
    token: str
    password: str


class UserLoginSchema(UserBase):
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str
