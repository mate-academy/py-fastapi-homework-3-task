from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators.accounts import validate_email, validate_password_strength


class EmailSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        validate_email(value.lower())
        return value


class EmailPasswordSchema(EmailSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_email(cls, value):
        validate_password_strength(value)
        return value


class MessageResponseSchema(BaseModel):
    message: str


class UserCreateRequestSchema(EmailPasswordSchema):
    pass


class UserCreateResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str


class UserLoginRequestSchema(EmailPasswordSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserActivateRequestSchema(EmailSchema):
    token: str


class CompletePasswordResetRequestSchema(EmailPasswordSchema):
    token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
