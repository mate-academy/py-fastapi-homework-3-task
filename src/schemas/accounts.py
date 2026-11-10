from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validator_user_password(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)

    @field_validator("email")
    @classmethod
    def validator_user_email(cls, email: str) -> str:
        return accounts_validators.validate_email(email)


class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str


class ActivateAccountRequest(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequest(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validator_user_password(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserLoginRequestSchema(UserBase):
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
