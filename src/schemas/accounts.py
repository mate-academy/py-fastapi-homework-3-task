import re
from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator
from typing import Optional


# Базовая схема для пользователя
class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")

        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")

        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lower letter.")

        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")

        if not re.search(r"[@$!%*?&#]", v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return v


# Ответ после регистрации
class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    model_config = ConfigDict(from_attributes=True)


# Оставлаем упрошенное имя для совместимости с роутами:
UserResponseSchema = UserRegistrationResponseSchema


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Запрос на активацию аккаунта
class UserActivationRequestSchema(UserBaseSchema):
    token: str


class PasswordResetCompleteResponseSchema(BaseModel):
    """Schema for password reset completion response."""

    message: str


# Запрос на восстановление пароля
class PasswordResetRequestSchema(UserBaseSchema):
    pass


# Завершение сброса пароля
class PasswordResetCompleteRequestSchema(UserBaseSchema):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength."""

        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")

        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")

        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lower letter.")

        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")

        special_chars = "@$!%*?#&"
        if not any(c in special_chars for c in v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )

        return v


# Запрос на логин
class UserLoginRequestSchema(UserBaseSchema):
    password: str


# Ответ с токенами
class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Запрос на обновление access токена
class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


# Ответ только с access токеном
class AccessTokenResponseSchema(BaseModel):
    access_token: str


# Оставлаем упрошенное имя для совместимости с роутами:
TokenRefreshResponseSchema = AccessTokenResponseSchema


class MessageResponseSchema(BaseModel):
    message: str
