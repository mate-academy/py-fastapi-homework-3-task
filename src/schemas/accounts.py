from pydantic import BaseModel, EmailStr, Field, field_validator
from database import accounts_validators


# ==========================================
# 1. REGISTRATION SCHEMAS
# ==========================================
class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., description="Secure password, minimum 8 characters")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        """
        Passes the incoming password string through the database account validator
        layer to enforce business rules.
        """
        if hasattr(accounts_validators, "validate_password"):
            try:
                accounts_validators.validate_password(value)
            except Exception as e:
                raise ValueError(str(e))
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True
    }


# ==========================================
# 2. ACTIVATION & REQUEST SCHEMAS
# ==========================================
class AccountActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserActivationRequestSchema(AccountActivationRequestSchema):
    """Alias schema supporting the exact structural mapping expected by routes/schemas init."""
    pass


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


# ==========================================
# 3. COMPLETION, LOGIN & REFRESH SCHEMAS
# ==========================================
class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., description="New secure password")

    @field_validator("password")
    @classmethod
    def validate_new_password_strength(cls, value: str) -> str:
        if hasattr(accounts_validators, "validate_password"):
            try:
                accounts_validators.validate_password(value)
            except Exception as e:
                raise ValueError(str(e))
        return value


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "from_attributes": True
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshSuccessResponseSchema(BaseModel):
    """
    Dedicated response schema strictly containing only the newly issued access token.
    Excludes refresh_token and token_type to align with strict task requirements.
    """
    access_token: str

    model_config = {
        "from_attributes": True
    }


class TokenRefreshResponseSchema(BaseModel):
    """Retained for structural initializers compatibility passes."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "from_attributes": True
    }


# ==========================================
# 4. GLOBAL SHARED RESPONSE SCHEMAS
# ==========================================
class MessageResponseSchema(BaseModel):
    message: str
