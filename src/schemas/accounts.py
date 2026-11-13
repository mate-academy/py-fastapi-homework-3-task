from pydantic import BaseModel, field_validator
from database.validators.accounts import validate_email, validate_password_strength


class UserBase(BaseModel):

    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        email = validate_email(value)

        return email


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        password = validate_password_strength(value)
        return password


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        email = validate_email(value)

        return email

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        password = validate_password_strength(value)

        return password


class UserRegistrationResponseSchema(UserBase):
    id: int
    email: str

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(UserBase):
    token: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserBase):
    email: str
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
