from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class ValidationSchema(BaseModel):

    @field_validator("email", check_fields=False)
    @classmethod
    def validate_email_is_correct(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator("password", check_fields=False)
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserBaseSchema(ValidationSchema):
    email: EmailStr
    password: str


class UserRegistrationRequestSchema(UserBaseSchema):
    pass


class UserRegistrationResponseSchema(ValidationSchema):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(ValidationSchema):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(ValidationSchema):
    email: EmailStr


class PasswordResetCompleteRequestSchema(PasswordResetRequestSchema):
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserBaseSchema):
    pass


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
