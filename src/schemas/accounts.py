from pydantic import BaseModel, EmailStr, ConfigDict


class UserBaseModel(BaseModel):
    email: EmailStr


class UserRegisterModel(UserBaseModel):
    password: str


class UserListModel(UserBaseModel):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivateModel(UserBaseModel):
    token: str


class UserPasswordResetModel(UserBaseModel):
    token: str
    password: str


class RefreshTokenRequestModel(BaseModel):
    refresh_token: str
