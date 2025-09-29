from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from src.database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def check_password_strength(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(UserBase):
    id: int
    model_config: ConfigDict = ConfigDict(from_attributes=True)


class ActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(ActivationRequestSchema):
    password: str

    @field_validator("password")
    def check_password_strength(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
