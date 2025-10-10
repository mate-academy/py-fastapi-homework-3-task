from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from database import accounts_validators


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserWithPasswordSchema(UserBaseSchema):
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationRequestSchema(UserWithPasswordSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str


class UserActivationRequestSchema(UserBaseSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(UserWithPasswordSchema):
    token: str


class UserLoginRequestSchema(UserBaseSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
