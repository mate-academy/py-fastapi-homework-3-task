from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBaseModel(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class UserRegistrationRequestSchema(UserBaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(UserBaseModel):
    token: str


class PasswordResetRequestSchema(UserBaseModel):
    pass


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
