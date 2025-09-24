from pydantic import (BaseModel,
                      EmailStr,
                      Field,
                      field_validator,
                      ConfigDict
                      )
from database.validators import accounts as validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=128)

    @field_validator("password")
    def validate_password(cls, value):
        return validators.validate_password_strength(value)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(..., min_length=1)


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    def validate_password(cls, value):
        return validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str = Field(..., min_length=1)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class UserLoginResponseSchema(BaseModel):
    pass
