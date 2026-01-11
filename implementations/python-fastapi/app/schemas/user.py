"""User schemas."""

from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    """Base user schema."""
    username: str
    email: EmailStr


class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """Schema for user login."""
    username: str
    password: str


class UserUpdate(BaseModel):
    """Schema for user update - VULNERABILITY: allows mass assignment."""
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    # VULNERABILITY: These fields should NOT be updatable by users
    role: Optional[str] = None
    is_active: Optional[bool] = None
    api_key: Optional[str] = None


class UserResponse(BaseModel):
    """User response - VULNERABILITY: exposes too much data."""
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    # VULNERABILITY: Sensitive data exposed (V03)
    ssn: Optional[str] = None
    credit_card: Optional[str] = None
    secret_note: Optional[str] = None
    api_key: Optional[str] = None

    class Config:
        from_attributes = True


class UserResponseSafe(BaseModel):
    """Safe user response (for comparison/documentation)."""
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class UserResponseLegacy(BaseModel):
    """Legacy API response - even more data exposed (V09)."""
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    ssn: Optional[str] = None
    credit_card: Optional[str] = None
    secret_note: Optional[str] = None
    api_key: Optional[str] = None
    password_hash: Optional[str] = None  # VULNERABILITY: Exposing password hash!
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
