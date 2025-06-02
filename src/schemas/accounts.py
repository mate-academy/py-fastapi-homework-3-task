from pydantic import (
    BaseModel,
    EmailStr,
    field_validator,
)

from database import accounts_validators


class UserBase(BaseModel):
    model_config = {"from_attributes": True}
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserResetPasswordRequestSchema(UserBase):
    pass


class UserResetPasswordCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class RefreshAccessTokenRequest(BaseModel):
    refresh_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
