"""Unit tests for authentication endpoints."""

import pytest


@pytest.mark.asyncio
class TestRegistration:
    """Test user registration."""

    async def test_register_success(self, client):
        """Test successful user registration."""
        response = await client.post(
            "/api/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "password123"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "user"
        assert data["is_active"] is True

    async def test_register_duplicate_username(self, client):
        """Test registration with existing username."""
        response = await client.post(
            "/api/register",
            json={
                "username": "admin",
                "email": "different@example.com",
                "password": "password123"
            }
        )

        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()

    async def test_register_duplicate_email(self, client):
        """Test registration with existing email."""
        response = await client.post(
            "/api/register",
            json={
                "username": "differentuser",
                "email": "admin@vulnapi.local",
                "password": "password123"
            }
        )

        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()

    async def test_register_invalid_email(self, client):
        """Test registration with invalid email."""
        response = await client.post(
            "/api/register",
            json={
                "username": "testuser",
                "email": "not-an-email",
                "password": "password123"
            }
        )

        assert response.status_code == 422


@pytest.mark.asyncio
class TestLogin:
    """Test user login."""

    async def test_login_success(self, client):
        """Test successful login."""
        response = await client.post(
            "/api/login",
            data={"username": "admin", "password": "admin123"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user_id"] == 1
        assert data["role"] == "admin"

    async def test_login_wrong_password(self, client):
        """Test login with wrong password."""
        response = await client.post(
            "/api/login",
            data={"username": "admin", "password": "wrongpassword"}
        )

        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()

    async def test_login_nonexistent_user(self, client):
        """Test login with non-existent user."""
        response = await client.post(
            "/api/login",
            data={"username": "nonexistent", "password": "password"}
        )

        assert response.status_code == 401
        assert "not found" in response.json()["detail"].lower()

    async def test_login_inactive_user(self, client, admin_token):
        """Test login with inactive user."""
        # First, deactivate a user
        headers = {"Authorization": f"Bearer {admin_token}"}
        await client.put(
            "/api/users/4",
            headers=headers,
            json={"is_active": False}
        )

        # Try to login as that user
        response = await client.post(
            "/api/login",
            data={"username": "bob", "password": "bob"}
        )

        assert response.status_code == 401

        # Reactivate the user
        await client.put(
            "/api/users/4",
            headers=headers,
            json={"is_active": True}
        )


@pytest.mark.asyncio
class TestMe:
    """Test /me endpoint."""

    async def test_get_me(self, client, user_token):
        """Test getting current user profile."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.get("/api/me", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "john"

    async def test_get_me_no_auth(self, client):
        """Test getting profile without authentication."""
        response = await client.get("/api/me")

        assert response.status_code == 401


@pytest.mark.asyncio
class TestTokenRefresh:
    """Test token refresh."""

    async def test_refresh_token(self, client, user_token):
        """Test refreshing a token."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.post("/api/token/refresh", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["access_token"] != user_token  # New token
