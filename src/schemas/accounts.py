from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

class BaseSchema(BaseModel):

