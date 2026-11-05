from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

class UserRegistrationRequestSchema(BaseModel):
    pass

class UserRegistrationResponseSchema(BaseModel):
    pass
class UserActivationRequestSchema(BaseModel):
    pass
class MessageResponseSchema(BaseModel):
    pass
class PasswordResetRequestSchema(BaseModel):
    pass
class PasswordResetCompleteRequestSchema(BaseModel):
    pass
class UserLoginResponseSchema(BaseModel):
    pass
class UserLoginRequestSchema(BaseModel):
    pass
class TokenRefreshRequestSchema(BaseModel):
    pass
class TokenRefreshResponseSchema(BaseModel):
    pass