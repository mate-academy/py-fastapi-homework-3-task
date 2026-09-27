from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class AccountBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(AccountBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str):
        return accounts_validators.validate_password_strength(value)


class AccountRead(AccountBase):
    model_config = ConfigDict(from_attributes=True)

    id: int


class TokenCheck(AccountBase):
    token: str


class ResetPassword(TokenCheck):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str):
        return accounts_validators.validate_password_strength(value)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class AccountLogin(AccountBase):
    password: str


class RefreshToken(BaseModel):
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


UserRegistrationResponseSchema = AccountRead
UserActivationRequestSchema = TokenCheck

PasswordResetRequestSchema = AccountBase
PasswordResetCompleteRequestSchema = ResetPassword

UserLoginResponseSchema = Token
UserLoginRequestSchema = AccountLogin

TokenRefreshRequestSchema = RefreshToken
