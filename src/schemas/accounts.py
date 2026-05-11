from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True
    }

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "from_attributes": True
    }


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "from_attributes": True
    }


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {
        "from_attributes": True
    }

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "from_attributes": True
    }


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = {
        "from_attributes": True
    }


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "from_attributes": True
    }
