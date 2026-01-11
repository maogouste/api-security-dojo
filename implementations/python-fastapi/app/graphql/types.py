"""GraphQL types for VulnAPI.

VULNERABILITIES:
- G03: Excessive data exposure (same as V03) - sensitive fields exposed
- G02: Nested queries enabled without depth limits
"""

import strawberry
from datetime import datetime
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from app.graphql.types import OrderType


@strawberry.type
class UserType:
    """
    User type with intentionally exposed sensitive fields.

    VULNERABILITY G03/V03: Exposes ssn, credit_card, secret_note, api_key
    VULNERABILITY G02: orders field enables deep nesting
    """
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    # VULNERABILITY: Sensitive data exposed
    ssn: Optional[str] = None
    credit_card: Optional[str] = None
    secret_note: Optional[str] = None
    api_key: Optional[str] = None

    @strawberry.field
    async def orders(self, info) -> List["OrderType"]:
        """
        Get user's orders.

        VULNERABILITY G02: Enables deep nesting (user -> orders -> user -> orders...)
        """
        from app.database import async_session_maker
        from app.models import Order
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(Order).where(Order.user_id == self.id)
            )
            orders = result.scalars().all()
            return [
                OrderType(
                    id=o.id,
                    user_id=o.user_id,
                    status=o.status,
                    total_amount=o.total_amount or 0.0,
                    shipping_address=o.shipping_address,
                    notes=o.notes,
                    created_at=o.created_at,
                )
                for o in orders
            ]


@strawberry.type
class ProductType:
    """
    Product type with intentionally exposed internal data.

    VULNERABILITY G03/V03: Exposes internal_notes and supplier_cost
    """
    id: int
    name: str
    description: Optional[str] = None
    price: float
    stock: int
    category: Optional[str] = None
    is_active: bool
    created_at: datetime

    # VULNERABILITY: Internal data exposed
    internal_notes: Optional[str] = None
    supplier_cost: Optional[float] = None


@strawberry.type
class OrderItemType:
    """Order item type."""
    id: int
    product_id: int
    quantity: int
    unit_price: float

    @strawberry.field
    async def product(self, info) -> ProductType:
        """Get the product for this order item."""
        from app.database import async_session_maker
        from app.models import Product
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(Product).where(Product.id == self.product_id)
            )
            p = result.scalar_one()
            return ProductType(
                id=p.id,
                name=p.name,
                description=p.description,
                price=p.price,
                stock=p.stock,
                category=p.category,
                is_active=p.is_active,
                created_at=p.created_at,
                internal_notes=p.internal_notes,
                supplier_cost=p.supplier_cost,
            )


@strawberry.type
class OrderType:
    """
    Order type with nested user access.

    VULNERABILITY G02: user field enables circular nesting
    """
    id: int
    user_id: int
    status: str
    total_amount: float
    shipping_address: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime

    @strawberry.field
    async def user(self, info) -> UserType:
        """
        Get the user who placed this order.

        VULNERABILITY G02: Enables deep nesting (order -> user -> orders -> user...)
        """
        from app.database import async_session_maker
        from app.models import User
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(User).where(User.id == self.user_id)
            )
            u = result.scalar_one()
            return UserType(
                id=u.id,
                username=u.username,
                email=u.email,
                role=u.role,
                is_active=u.is_active,
                created_at=u.created_at,
                ssn=u.ssn,
                credit_card=u.credit_card,
                secret_note=u.secret_note,
                api_key=u.api_key,
            )

    @strawberry.field
    async def items(self, info) -> List[OrderItemType]:
        """Get order items."""
        from app.database import async_session_maker
        from app.models import OrderItem
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(OrderItem).where(OrderItem.order_id == self.id)
            )
            items = result.scalars().all()
            return [
                OrderItemType(
                    id=i.id,
                    product_id=i.product_id,
                    quantity=i.quantity,
                    unit_price=i.unit_price,
                )
                for i in items
            ]


@strawberry.type
class AuthPayload:
    """Authentication response."""
    access_token: str
    token_type: str = "bearer"
    user_id: int
    role: str


@strawberry.type
class ChallengeType:
    """Challenge information."""
    id: str
    name: str
    category: str
    difficulty: str
    points: int
    description: str
    hints: List[str]
    completed: bool = False


@strawberry.type
class ProgressType:
    """User progress information."""
    total_challenges: int
    completed: int
    total_points: int
    earned_points: int
    challenges: List[ChallengeType]


@strawberry.type
class FlagResultType:
    """Flag submission result."""
    success: bool
    message: str
    points: Optional[int] = None


# Input types for mutations
@strawberry.input
class RegisterInput:
    """Input for user registration."""
    username: str
    email: str
    password: str


@strawberry.input
class UpdateUserInput:
    """
    Input for user update.

    VULNERABILITY G05/V05: Allows updating role and is_active (mass assignment)
    """
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None  # VULNERABLE: Should not be user-modifiable
    is_active: Optional[bool] = None  # VULNERABLE: Should not be user-modifiable


@strawberry.input
class ProductInput:
    """Input for product creation/update."""
    name: str
    description: Optional[str] = None
    price: float
    stock: int = 0
    category: Optional[str] = None
