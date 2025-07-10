from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "password": "SecurePassword123!"
                }
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": 1,
                    "email": "user@example.com"
                }
            ]
        }
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "test@example.com",
                    "token": "activation_token"
                }
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Activation token cannot be empty")
        return value.strip()


class UserActivationResponseSchema(BaseModel):
    message: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "User account activated successfully."
                }
            ]
        }
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "test@example.com"
                }
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class PasswordResetResponseSchema(BaseModel):
    message: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "If you are registered, you will receive an email with instructions."
                }
            ]
        }
    }


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "testuser@example.com",
                    "token": "valid-reset-token",
                    "password": "NewStrongPassword123!"
                }
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Password reset token cannot be empty")
        return value.strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Password reset successfully."
                }
            ]
        }
    }


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "password": "UserPassword123!"
                }
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Password cannot be empty")
        return value


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer"
                }
            ]
        }
    }


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "refresh_token": "example_refresh_token"
                }
            ]
        }
    }

    @field_validator("refresh_token")
    @classmethod
    def validate_refresh_token(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Refresh token cannot be empty")
        return value.strip()


class RefreshTokenResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "new_access_token"
                }
            ]
        }
    }
