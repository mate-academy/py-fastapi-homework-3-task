from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

# Write your code here
#     UserRegistrationRequestSchema,
#     UserRegistrationResponseSchema,
#     UserActivationRequestSchema,
#     MessageResponseSchema,
#     PasswordResetRequestSchema,
#     PasswordResetCompleteRequestSchema,
#     UserLoginResponseSchema,
#     UserLoginRequestSchema,
#     TokenRefreshRequestSchema,
#     TokenRefreshResponseSchema



class ActivationTokenSchema(BaseModel):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class BaseSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(BaseSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr
    activation_token: ActivationTokenSchema

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class PasswordResetCompleteRequestSchema(BaseSchema):
    token: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseSchema):
    pass


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
