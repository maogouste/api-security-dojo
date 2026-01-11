"""Order schemas."""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class OrderItemCreate(BaseModel):
    """Schema for creating an order item."""
    product_id: int
    quantity: int = 1


class OrderItemResponse(BaseModel):
    """Order item response."""
    id: int
    product_id: int
    quantity: int
    unit_price: float

    class Config:
        from_attributes = True


class OrderCreate(BaseModel):
    """Schema for creating an order."""
    shipping_address: Optional[str] = None
    notes: Optional[str] = None
    items: List[OrderItemCreate]


class OrderResponse(BaseModel):
    """Order response."""
    id: int
    user_id: int
    status: str
    total_amount: float
    shipping_address: Optional[str]
    notes: Optional[str]
    created_at: datetime
    items: List[OrderItemResponse] = []

    class Config:
        from_attributes = True
