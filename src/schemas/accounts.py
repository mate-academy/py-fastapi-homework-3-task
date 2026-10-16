from pydantic import BaseModel, EmailStr, Field, field_validator


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if len(password) < 8:
            raise ValueError(
                "Password must contain at least 8 characters."
            )

        if not any(char.isupper() for char in password):
            raise ValueError(
                "Password must contain at least one uppercase letter."
            )

        if not any(char.islower() for char in password):
            raise ValueError(
                "Password must contain at least one lower letter."
            )

        if not any(char.isdigit() for char in password):
            raise ValueError(
                "Password must contain at least one digit."
            )

        special_characters = "@$!%*?#&"
        if not any(char in special_characters for char in password):
            raise ValueError(
                "Password must contain at least one special character: "
                "@, $, !, %, *, ?, #, &."
            )

        return password


class UserRead(UserBase):
    id: int

    model_config = {"from_attributes": True}


class UserActivate(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetComplete(BaseModel):
    email: EmailStr
    token: str = Field(min_length=1)
    password: str = Field(min_length=8)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResponse(Token):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str


class MessageResponse(BaseModel):
    message: str
