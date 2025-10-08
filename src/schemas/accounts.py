from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field

from database import accounts_validators


class EmailSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> EmailStr:
        return accounts_validators.validate_email(value)


class UserRegistrationRequestSchema(EmailSchema):
    model_config = ConfigDict(
        from_attributes=True,
    )
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(EmailSchema):
    model_config = ConfigDict(
        from_attributes=True,
    )
    id: int


class UserActivationRequestSchema(EmailSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(EmailSchema):
    pass


class PasswordResetCompleteRequestSchema(EmailSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field("bearer")


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
