import re

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, ClassVar


# --- Реєстрація користувача ---
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str  # ПЕРЕКОНАЙТЕСЯ, ЩО ТУТ БІЛЬШЕ НЕМАЄ Field(min_length=8)

    TEST_SPECIAL_CHARS: ClassVar[str] = r"[@\$!%*?#&]"

    @field_validator("password")
    def validate_password_strength(cls, v):
        # 1. Довжина (якщо її тут немає, то Pydantic спрацює сам)
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")

        # 2. Велика літера (має бути тут, щоб зловити 'nodigitnorupper@' ПЕРШОЮ)
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")

        # 3. Цифра (йде після великої літери)
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit.")

        # 4. Мала літера
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lower letter.")

        # 5. Спеціальний символ
        if not re.search(cls.TEST_SPECIAL_CHARS, v):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )

        return v


class UserRegistrationResponseSchema(BaseModel):
    """Схема відповіді після успішної реєстрації користувача."""

    id: int = Field(..., example=1)
    email: EmailStr = Field(..., example="user@example.com")

    class Config:
        from_attributes = True


# --- Активація облікового запису користувача ---
class UserActivationRequestSchema(BaseModel):
    """Схема запиту для активації облікового запису користувача."""

    email: EmailStr = Field(..., example="test@example.com")
    token: str = Field(..., example="activation_token_string")


# --- Запит токена скидання пароля ---
class PasswordResetRequestSchema(BaseModel):
    """Схема запиту для отримання токена скидання пароля."""

    email: EmailStr = Field(..., example="test@example.com")


# --- Завершення скидання пароля ---
class PasswordResetCompleteRequestSchema(BaseModel):
    """Схема запиту для завершення скидання пароля."""

    email: EmailStr = Field(..., example="testuser@example.com")
    token: str = Field(..., example="valid-reset-token")
    password: str = Field(
        ..., min_length=8, max_length=64, example="NewStrongPassword123!"
    )


# --- Вхід користувача ---
class UserLoginRequestSchema(BaseModel):
    """Схема запиту для входу користувача."""

    email: EmailStr = Field(..., example="user@example.com")
    password: str = Field(..., example="UserPassword123!")


class UserLoginResponseSchema(BaseModel):
    """Схема відповіді після успішного входу користувача."""

    access_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    refresh_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    token_type: str = Field(..., example="bearer")
    expires_in: int = Field(..., example=3600)


# --- Оновлення токена доступу ---
class TokenRefreshRequestSchema(BaseModel):
    """Схема запиту для оновлення токена доступу."""

    refresh_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")


class TokenRefreshResponseSchema(BaseModel):
    """Схема відповіді після успішного оновлення токена доступу."""

    access_token: str = Field(..., example="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    refresh_token: str = Field(..., description="Newly issued refresh token.")
    token_type: str = Field("bearer", description="Type of the token.")
    expires_in: int = Field(..., description="Access token expiration time in seconds.")


# --- Загальна схема повідомлень ---
class MessageResponseSchema(BaseModel):
    """Загальна схема для повідомлень у відповідях API."""

    message: str = Field(..., example="Операція успішна.")
