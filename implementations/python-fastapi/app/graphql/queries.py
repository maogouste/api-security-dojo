"""GraphQL query resolvers.

VULNERABILITIES:
- G01: Introspection enabled (default behavior)
- G02: No query depth limits (nested queries possible)
- G03: No complexity limits (can request all data)
- G05: No authentication checks on sensitive queries
"""

import strawberry
from typing import List, Optional
from strawberry.types import Info
from sqlalchemy import select
import json

from app.database import async_session_maker
from app.models import User, Product, Order
from app.graphql.types import (
    UserType, ProductType, OrderType,
    ChallengeType, ProgressType
)


@strawberry.type
class Query:
    """
    GraphQL Query type.

    VULNERABILITY G01: Introspection is enabled by default.
    VULNERABILITY G02: No depth/complexity limits on queries.
    VULNERABILITY G05: No authentication required for sensitive data.
    """

    @strawberry.field
    async def users(self, info: Info) -> List[UserType]:
        """
        Get all users.

        VULNERABILITY G05: No authentication check!
        Anyone can query all users with sensitive data.

        Example exploit:
        query { users { id username email ssn creditCard secretNote apiKey } }
        """
        async with async_session_maker() as db:
            result = await db.execute(select(User))
            users = result.scalars().all()
            return [
                UserType(
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
                for u in users
            ]

    @strawberry.field
    async def user(self, info: Info, id: int) -> Optional[UserType]:
        """
        Get a user by ID.

        VULNERABILITY G05: No authorization check - any user can access any user's data.
        """
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.id == id))
            u = result.scalar_one_or_none()
            if not u:
                return None
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
    async def me(self, info: Info) -> Optional[UserType]:
        """
        Get current authenticated user.

        This one actually checks auth, but still exposes sensitive data.
        """
        context = info.context
        if not context.is_authenticated:
            return None

        async with async_session_maker() as db:
            result = await db.execute(
                select(User).where(User.id == context.current_user.id)
            )
            u = result.scalar_one_or_none()
            if not u:
                return None
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
    async def products(self, info: Info) -> List[ProductType]:
        """
        Get all products.

        VULNERABILITY: Exposes internal_notes and supplier_cost.
        """
        async with async_session_maker() as db:
            result = await db.execute(
                select(Product).where(Product.is_active == True)
            )
            products = result.scalars().all()
            return [
                ProductType(
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
                for p in products
            ]

    @strawberry.field
    async def product(self, info: Info, id: int) -> Optional[ProductType]:
        """Get a product by ID."""
        async with async_session_maker() as db:
            result = await db.execute(select(Product).where(Product.id == id))
            p = result.scalar_one_or_none()
            if not p:
                return None
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

    @strawberry.field
    async def orders(self, info: Info) -> List[OrderType]:
        """
        Get all orders.

        VULNERABILITY G05: No authentication - exposes all orders!
        """
        async with async_session_maker() as db:
            result = await db.execute(select(Order))
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

    @strawberry.field
    async def order(self, info: Info, id: int) -> Optional[OrderType]:
        """
        Get an order by ID.

        VULNERABILITY G05: No ownership check.
        """
        async with async_session_maker() as db:
            result = await db.execute(select(Order).where(Order.id == id))
            o = result.scalar_one_or_none()
            if not o:
                return None
            return OrderType(
                id=o.id,
                user_id=o.user_id,
                status=o.status,
                total_amount=o.total_amount or 0.0,
                shipping_address=o.shipping_address,
                notes=o.notes,
                created_at=o.created_at,
            )

    @strawberry.field
    async def challenges(self, info: Info) -> List[ChallengeType]:
        """Get all available challenges."""
        # Load from challenges.json
        try:
            with open("../../specs/challenges.json") as f:
                data = json.load(f)

            return [
                ChallengeType(
                    id=c["id"],
                    name=c["name"],
                    category=c["category"],
                    difficulty=c["difficulty"],
                    points=c["points"],
                    description=c["description"],
                    hints=c["hints"],
                    completed=False,
                )
                for c in data.get("challenges", [])
            ]
        except Exception:
            # Fallback: return empty list
            return []

    @strawberry.field
    async def nested_test(self, info: Info, depth: int = 5) -> str:
        """
        Test query for demonstrating G02 (nested queries).

        VULNERABILITY G02: No depth limit - can cause DoS with deep nesting.

        Example:
        query {
          users {
            orders {
              user {
                orders {
                  user {
                    username
                  }
                }
              }
            }
          }
        }
        """
        return f"Nested depth allowed: unlimited (requested: {depth})"
