"""Product schemas."""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ProductBase(BaseModel):
    """Base product schema."""
    name: str
    description: Optional[str] = None
    price: float
    category: Optional[str] = None


class ProductCreate(ProductBase):
    """Schema for creating a product."""
    stock: int = 0


class ProductUpdate(BaseModel):
    """Schema for updating a product."""
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    stock: Optional[int] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None


class ProductResponse(BaseModel):
    """Product response - VULNERABILITY: exposes internal data."""
    id: int
    name: str
    description: Optional[str]
    price: float
    stock: int
    category: Optional[str]
    is_active: bool
    created_at: datetime

    # VULNERABILITY: Internal data exposed (V03)
    internal_notes: Optional[str] = None
    supplier_cost: Optional[float] = None

    class Config:
        from_attributes = True


class ProductResponseSafe(BaseModel):
    """Safe product response (for comparison)."""
    id: int
    name: str
    description: Optional[str]
    price: float
    stock: int
    category: Optional[str]
    is_active: bool

    class Config:
        from_attributes = True
