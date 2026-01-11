"""Unit tests for products endpoints."""

import pytest


@pytest.mark.asyncio
class TestListProducts:
    """Test product listing."""

    async def test_list_products(self, client):
        """Test listing all products."""
        response = await client.get("/api/products")

        assert response.status_code == 200
        products = response.json()
        assert len(products) >= 5  # At least 5 active products

    async def test_list_products_hides_inactive(self, client):
        """Test that inactive products are hidden in normal listing."""
        response = await client.get("/api/products")

        products = response.json()
        # Secret product is inactive and should not appear
        names = [p["name"] for p in products]
        assert "Secret Product" not in names

    async def test_search_products(self, client):
        """Test searching products."""
        response = await client.get("/api/products?search=laptop")

        assert response.status_code == 200
        products = response.json()
        assert len(products) >= 1
        assert any("laptop" in p["name"].lower() for p in products)


@pytest.mark.asyncio
class TestGetProduct:
    """Test getting a single product."""

    async def test_get_product(self, client):
        """Test getting a product by ID."""
        response = await client.get("/api/products/1")

        assert response.status_code == 200
        product = response.json()
        assert product["id"] == 1
        assert product["name"] == "Laptop Pro X1"

    async def test_get_product_not_found(self, client):
        """Test getting a non-existent product."""
        response = await client.get("/api/products/99999")

        assert response.status_code == 404


@pytest.mark.asyncio
class TestCreateProduct:
    """Test product creation."""

    async def test_create_product_as_admin(self, client, admin_token):
        """Test creating a product as admin."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = await client.post(
            "/api/products",
            headers=headers,
            json={
                "name": "New Product",
                "description": "A new test product",
                "price": 99.99,
                "stock": 10,
                "category": "Test"
            }
        )

        assert response.status_code == 200
        product = response.json()
        assert product["name"] == "New Product"
        assert product["price"] == 99.99

    async def test_create_product_as_user_forbidden(self, client, user_token):
        """Test that regular users cannot create products."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.post(
            "/api/products",
            headers=headers,
            json={
                "name": "Unauthorized Product",
                "price": 10.00
            }
        )

        assert response.status_code == 403

    async def test_create_product_no_auth(self, client):
        """Test creating a product without authentication."""
        response = await client.post(
            "/api/products",
            json={
                "name": "No Auth Product",
                "price": 10.00
            }
        )

        assert response.status_code == 401


@pytest.mark.asyncio
class TestUpdateProduct:
    """Test product updates."""

    async def test_update_product_as_admin(self, client, admin_token):
        """Test updating a product as admin."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = await client.put(
            "/api/products/2",
            headers=headers,
            json={"price": 59.99}
        )

        assert response.status_code == 200
        product = response.json()
        assert product["price"] == 59.99

        # Restore original price
        await client.put(
            "/api/products/2",
            headers=headers,
            json={"price": 49.99}
        )

    async def test_update_product_as_user_forbidden(self, client, user_token):
        """Test that regular users cannot update products."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.put(
            "/api/products/2",
            headers=headers,
            json={"price": 1.00}
        )

        assert response.status_code == 403


@pytest.mark.asyncio
class TestDeleteProduct:
    """Test product deletion."""

    async def test_delete_product_as_admin(self, client, admin_token):
        """Test deleting a product as admin."""
        # First create a product to delete
        headers = {"Authorization": f"Bearer {admin_token}"}
        create_response = await client.post(
            "/api/products",
            headers=headers,
            json={
                "name": "To Delete",
                "price": 1.00
            }
        )
        product_id = create_response.json()["id"]

        # Delete it
        response = await client.delete(
            f"/api/products/{product_id}",
            headers=headers
        )

        assert response.status_code == 200

        # Verify it's deleted
        get_response = await client.get(f"/api/products/{product_id}")
        assert get_response.status_code == 404
