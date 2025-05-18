import re
from pydantic import BaseModel, EmailStr, field_validator


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")

        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"[@$!%*?#&]", v):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return v


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class UserLoginRequestSchema(BaseModel):
    password: str
    email: EmailStr


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    id: int
    email: str
    group_id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "token": "activation_token_string"
            }
        }
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(BaseModel):
    id: int
    email: str
    reset_token: str
    token_type: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    password: str
    token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
