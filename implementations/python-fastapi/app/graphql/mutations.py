"""GraphQL mutation resolvers.

VULNERABILITIES:
- G05: Missing authorization checks on mutations
- V05: Mass assignment vulnerability in updateUser
"""

import strawberry
from typing import Optional
from datetime import timedelta
from strawberry.types import Info
from sqlalchemy import select

from app.database import async_session_maker
from app.models import User, Product
from app.config import settings
from app.vulnerabilities import (
    get_password_hash,
    verify_password,
    create_access_token,
)
from app.graphql.types import (
    UserType, ProductType, AuthPayload, FlagResultType,
    RegisterInput, UpdateUserInput, ProductInput,
)


@strawberry.type
class Mutation:
    """
    GraphQL Mutation type.

    VULNERABILITY G05: Most mutations lack proper authorization.
    VULNERABILITY G03: Batching allows multiple mutations in one request.
    """

    @strawberry.mutation
    async def register(self, info: Info, input: RegisterInput) -> AuthPayload:
        """Register a new user."""
        async with async_session_maker() as db:
            # Check if username exists
            result = await db.execute(
                select(User).where(User.username == input.username)
            )
            if result.scalar_one_or_none():
                raise Exception("Username already registered")

            # Check if email exists
            result = await db.execute(
                select(User).where(User.email == input.email)
            )
            if result.scalar_one_or_none():
                raise Exception("Email already registered")

            # Create user (no password validation - vulnerable)
            user = User(
                username=input.username,
                email=input.email,
                password_hash=get_password_hash(input.password),
                role="user",
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)

            # Create token
            access_token = create_access_token(
                data={
                    "sub": user.username,
                    "user_id": user.id,
                    "role": user.role,
                },
                expires_delta=timedelta(minutes=settings.jwt_expiration_minutes)
            )

            return AuthPayload(
                access_token=access_token,
                token_type="bearer",
                user_id=user.id,
                role=user.role,
            )

    @strawberry.mutation
    async def login(
        self,
        info: Info,
        username: str,
        password: str
    ) -> AuthPayload:
        """Login and get access token."""
        async with async_session_maker() as db:
            result = await db.execute(
                select(User).where(User.username == username)
            )
            user = result.scalar_one_or_none()

            if not user:
                # VULNERABILITY: Different error for non-existent user
                raise Exception("User not found")

            if not verify_password(password, user.password_hash):
                # VULNERABILITY: Different error for wrong password
                raise Exception("Incorrect password")

            if not user.is_active:
                raise Exception("User account is disabled")

            access_token = create_access_token(
                data={
                    "sub": user.username,
                    "user_id": user.id,
                    "role": user.role,
                },
                expires_delta=timedelta(minutes=settings.jwt_expiration_minutes)
            )

            return AuthPayload(
                access_token=access_token,
                token_type="bearer",
                user_id=user.id,
                role=user.role,
            )

    @strawberry.mutation
    async def update_user(
        self,
        info: Info,
        id: int,
        input: UpdateUserInput
    ) -> Optional[UserType]:
        """
        Update a user.

        VULNERABILITY G05: No authorization check - anyone can update anyone.
        VULNERABILITY V05: Mass assignment - can change role and is_active.

        Example exploit:
        mutation {
          updateUser(id: 2, input: { role: "admin" }) {
            id username role
          }
        }
        """
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.id == id))
            user = result.scalar_one_or_none()

            if not user:
                return None

            # VULNERABILITY: Mass assignment - all fields applied
            if input.username is not None:
                user.username = input.username
            if input.email is not None:
                user.email = input.email
            if input.password is not None:
                user.password_hash = get_password_hash(input.password)
            if input.role is not None:
                user.role = input.role  # VULNERABLE!
            if input.is_active is not None:
                user.is_active = input.is_active  # VULNERABLE!

            await db.commit()
            await db.refresh(user)

            return UserType(
                id=user.id,
                username=user.username,
                email=user.email,
                role=user.role,
                is_active=user.is_active,
                created_at=user.created_at,
                ssn=user.ssn,
                credit_card=user.credit_card,
                secret_note=user.secret_note,
                api_key=user.api_key,
            )

    @strawberry.mutation
    async def delete_user(self, info: Info, id: int) -> bool:
        """
        Delete a user.

        VULNERABILITY G05: No authorization check.
        VULNERABILITY V10: No audit logging.
        """
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.id == id))
            user = result.scalar_one_or_none()

            if not user:
                return False

            await db.delete(user)
            await db.commit()
            return True

    @strawberry.mutation
    async def create_product(
        self,
        info: Info,
        input: ProductInput
    ) -> ProductType:
        """
        Create a new product.

        VULNERABILITY G05: Should require admin role but doesn't check.
        """
        async with async_session_maker() as db:
            product = Product(
                name=input.name,
                description=input.description,
                price=input.price,
                stock=input.stock,
                category=input.category,
            )
            db.add(product)
            await db.commit()
            await db.refresh(product)

            return ProductType(
                id=product.id,
                name=product.name,
                description=product.description,
                price=product.price,
                stock=product.stock,
                category=product.category,
                is_active=product.is_active,
                created_at=product.created_at,
                internal_notes=product.internal_notes,
                supplier_cost=product.supplier_cost,
            )

    @strawberry.mutation
    async def update_product(
        self,
        info: Info,
        id: int,
        input: ProductInput
    ) -> Optional[ProductType]:
        """
        Update a product.

        VULNERABILITY G05: No admin check.
        """
        async with async_session_maker() as db:
            result = await db.execute(select(Product).where(Product.id == id))
            product = result.scalar_one_or_none()

            if not product:
                return None

            product.name = input.name
            product.description = input.description
            product.price = input.price
            product.stock = input.stock
            product.category = input.category

            await db.commit()
            await db.refresh(product)

            return ProductType(
                id=product.id,
                name=product.name,
                description=product.description,
                price=product.price,
                stock=product.stock,
                category=product.category,
                is_active=product.is_active,
                created_at=product.created_at,
                internal_notes=product.internal_notes,
                supplier_cost=product.supplier_cost,
            )

    @strawberry.mutation
    async def delete_product(self, info: Info, id: int) -> bool:
        """
        Delete a product.

        VULNERABILITY G05: No admin check.
        """
        async with async_session_maker() as db:
            result = await db.execute(select(Product).where(Product.id == id))
            product = result.scalar_one_or_none()

            if not product:
                return False

            await db.delete(product)
            await db.commit()
            return True

    @strawberry.mutation
    async def submit_flag(
        self,
        info: Info,
        challenge_id: str,
        flag: str
    ) -> FlagResultType:
        """Submit a flag for a challenge."""
        from app.models import Flag, FlagSubmission

        context = info.context
        if not context.is_authenticated:
            return FlagResultType(
                success=False,
                message="Authentication required",
                points=None,
            )

        async with async_session_maker() as db:
            # Find the flag
            result = await db.execute(
                select(Flag).where(Flag.challenge_id == challenge_id)
            )
            db_flag = result.scalar_one_or_none()

            if not db_flag:
                return FlagResultType(
                    success=False,
                    message="Challenge not found",
                    points=None,
                )

            is_correct = db_flag.flag_value == flag

            # Record submission
            submission = FlagSubmission(
                user_id=context.current_user.id,
                challenge_id=challenge_id,
                submitted_flag=flag,
                is_correct=1 if is_correct else 0,
            )
            db.add(submission)
            await db.commit()

            if is_correct:
                return FlagResultType(
                    success=True,
                    message="Correct! Challenge completed.",
                    points=100,  # TODO: Get from challenges.json
                )
            else:
                return FlagResultType(
                    success=False,
                    message="Incorrect flag. Try again!",
                    points=None,
                )
