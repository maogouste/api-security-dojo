"""Authentication schemas."""

from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    """JWT Token response."""
    access_token: str
    token_type: str = "bearer"
    # VULNERABILITY: Exposing too much info
    user_id: Optional[int] = None
    role: Optional[str] = None


class TokenData(BaseModel):
    """Token payload data."""
    sub: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[str] = None
