from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    field_validator,
)

from database.validators import accounts


class UserBaseSchema(BaseModel):
    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts.validate_email(value)


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBaseSchema):
    model_config = ConfigDict(from_attributes=True)

    id: int


class MessageResponseSchema(BaseModel):
    message: str


class UserActivationRequestSchema(UserBaseSchema):
    token: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(
    UserRegistrationRequestSchema
):
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
