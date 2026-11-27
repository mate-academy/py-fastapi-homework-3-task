from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = ConfigDict(from_attributes=True)


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
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginResponseSchema(TokenResponseSchema):
    pass


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshRequestSchema(RefreshTokenRequestSchema):
    pass


class AccessTokenResponseSchema(BaseModel):
    access_token: str


class TokenRefreshResponseSchema(AccessTokenResponseSchema):
    pass
