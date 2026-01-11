"""Database seeding with initial data."""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import async_session_maker
from app.models import User, Product, Order, OrderItem, Flag
from app.vulnerabilities import get_password_hash


async def seed_database():
    """Seed the database with initial data."""
    async with async_session_maker() as db:
        # Check if already seeded
        result = await db.execute(select(User).limit(1))
        if result.scalar_one_or_none():
            return  # Already seeded

        # Create users
        users = [
            User(
                username="admin",
                email="admin@vulnapi.local",
                password_hash=get_password_hash("admin123"),  # Weak password
                role="admin",
                ssn="123-45-6789",
                credit_card="4111-1111-1111-1111",
                secret_note="VULNAPI{bola_user_data_exposed}",  # V01 flag
                api_key="admin-api-key-12345",
            ),
            User(
                username="john",
                email="john@example.com",
                password_hash=get_password_hash("password123"),
                role="user",
                ssn="987-65-4321",
                credit_card="5500-0000-0000-0004",
                secret_note="John's private notes",
            ),
            User(
                username="jane",
                email="jane@example.com",
                password_hash=get_password_hash("jane2024"),
                role="user",
                ssn="456-78-9012",
                credit_card="3400-0000-0000-009",
                secret_note="Jane's secret data",
            ),
            User(
                username="bob",
                email="bob@example.com",
                password_hash=get_password_hash("bob"),  # Very weak password
                role="user",
            ),
            User(
                username="service_account",
                email="service@vulnapi.local",
                password_hash=get_password_hash("svc_password_2024"),
                role="superadmin",
                api_key="VULNAPI{jwt_weak_secret_cracked}",  # V02 flag
                secret_note="Service account - do not delete",
            ),
        ]

        for user in users:
            db.add(user)

        # Create products
        products = [
            Product(
                name="Laptop Pro X1",
                description="High-performance laptop for professionals",
                price=1299.99,
                stock=50,
                category="Electronics",
                internal_notes="VULNAPI{exposure_internal_data_leak}",  # V03 flag
                supplier_cost=850.00,
            ),
            Product(
                name="Wireless Mouse",
                description="Ergonomic wireless mouse",
                price=49.99,
                stock=200,
                category="Electronics",
                internal_notes="Supplier: TechCorp, Margin: 60%",
                supplier_cost=20.00,
            ),
            Product(
                name="USB-C Hub",
                description="7-in-1 USB-C hub with HDMI",
                price=79.99,
                stock=150,
                category="Electronics",
                internal_notes="Best seller Q4 2024",
                supplier_cost=35.00,
            ),
            Product(
                name="Mechanical Keyboard",
                description="RGB mechanical keyboard with Cherry MX switches",
                price=149.99,
                stock=75,
                category="Electronics",
                supplier_cost=80.00,
            ),
            Product(
                name="4K Monitor",
                description="27-inch 4K IPS monitor",
                price=399.99,
                stock=30,
                category="Electronics",
                internal_notes="Discontinued model - clearance",
                supplier_cost=250.00,
            ),
            Product(
                name="Secret Product",
                description="VULNAPI{sqli_database_dumped}",  # V06 flag (found via SQLi)
                price=9999.99,
                stock=1,
                category="Hidden",
                is_active=False,  # Not visible in normal queries
                internal_notes="This product should never be visible",
            ),
        ]

        for product in products:
            db.add(product)

        # Create flags for challenges
        flags = [
            Flag(
                challenge_id="V01",
                flag_value="VULNAPI{bola_user_data_exposed}",
                description="Found by accessing another user's data via BOLA",
            ),
            Flag(
                challenge_id="V02",
                flag_value="VULNAPI{jwt_weak_secret_cracked}",
                description="Found by cracking the weak JWT secret or exploiting algorithm confusion",
            ),
            Flag(
                challenge_id="V03",
                flag_value="VULNAPI{exposure_internal_data_leak}",
                description="Found in excessive data exposure in API responses",
            ),
            Flag(
                challenge_id="V04",
                flag_value="VULNAPI{ratelimit_bruteforce_success}",
                description="Demonstrated by brute forcing login without rate limiting",
            ),
            Flag(
                challenge_id="V05",
                flag_value="VULNAPI{mass_assignment_privilege_escalation}",
                description="Found by escalating privileges via mass assignment",
            ),
            Flag(
                challenge_id="V06",
                flag_value="VULNAPI{sqli_database_dumped}",
                description="Found by exploiting SQL injection in product search",
            ),
            Flag(
                challenge_id="V07",
                flag_value="VULNAPI{cmd_injection_rce_achieved}",
                description="Found by achieving RCE via command injection",
            ),
            Flag(
                challenge_id="V08",
                flag_value="VULNAPI{misconfig_cors_headers_missing}",
                description="Identified by checking security headers and CORS config",
            ),
            Flag(
                challenge_id="V09",
                flag_value="VULNAPI{version_legacy_api_exposed}",
                description="Found by discovering and exploiting old API version",
            ),
            Flag(
                challenge_id="V10",
                flag_value="VULNAPI{logging_blind_attack_undetected}",
                description="Demonstrated by performing attacks without logging",
            ),
            # GraphQL challenges (G01-G05)
            Flag(
                challenge_id="G01",
                flag_value="VULNAPI{graphql_introspection_schema_leaked}",
                description="Found by using GraphQL introspection to discover schema",
            ),
            Flag(
                challenge_id="G02",
                flag_value="VULNAPI{graphql_depth_resource_exhaustion}",
                description="Demonstrated by exploiting unlimited query depth",
            ),
            Flag(
                challenge_id="G03",
                flag_value="VULNAPI{graphql_batch_rate_limit_bypass}",
                description="Found by batching multiple operations in one request",
            ),
            Flag(
                challenge_id="G04",
                flag_value="VULNAPI{graphql_suggestions_field_enumeration}",
                description="Found by using error messages to enumerate fields",
            ),
            Flag(
                challenge_id="G05",
                flag_value="VULNAPI{graphql_authz_sensitive_data_exposed}",
                description="Found by accessing sensitive data without authentication",
            ),
        ]

        for flag in flags:
            db.add(flag)

        await db.commit()
        print("[*] Database seeded successfully!")


async def create_sample_orders(db: AsyncSession):
    """Create sample orders (called separately if needed)."""
    # Get users and products
    users_result = await db.execute(select(User).where(User.role == "user"))
    users = users_result.scalars().all()

    products_result = await db.execute(select(Product).where(Product.is_active == True))
    products = products_result.scalars().all()

    if not users or not products:
        return

    # Create a sample order for first user
    order = Order(
        user_id=users[0].id,
        status="confirmed",
        shipping_address="123 Main St, City, Country",
        notes="Please deliver in the morning",
    )
    db.add(order)
    await db.flush()

    # Add items
    total = 0
    for i, product in enumerate(products[:2]):
        item = OrderItem(
            order_id=order.id,
            product_id=product.id,
            quantity=i + 1,
            unit_price=product.price,
        )
        db.add(item)
        total += product.price * (i + 1)

    order.total_amount = total
    await db.commit()
