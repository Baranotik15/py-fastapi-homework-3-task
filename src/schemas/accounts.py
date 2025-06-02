from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from src.database.validators.accounts import (
    validate_password_strength,
)
from database import accounts_validators


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, email):
        return email.lower()

    @field_validator("password")
    @classmethod
    def validate_password_field(cls, value: str) -> str:
        return validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str