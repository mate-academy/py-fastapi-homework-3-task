from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators, UserModel


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def password_validator(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(UserBase):
    token: str = Field(max_lenght=64)


class MessageResponseSchema(BaseModel):
    detail: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    password: str
    token: str = Field(max_lenght=64)

    @field_validator("password")
    def password_validator(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def password_validator(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
