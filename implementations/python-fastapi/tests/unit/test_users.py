"""Unit tests for users endpoints."""

import pytest


@pytest.mark.asyncio
class TestListUsers:
    """Test user listing."""

    async def test_list_users_authenticated(self, client, user_token):
        """Test listing users when authenticated."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.get("/api/users", headers=headers)

        assert response.status_code == 200
        users = response.json()
        assert len(users) >= 5

    async def test_list_users_no_auth(self, client):
        """Test listing users without authentication."""
        response = await client.get("/api/users")

        # Should require auth (even if BOLA exists)
        assert response.status_code == 401


@pytest.mark.asyncio
class TestGetUser:
    """Test getting a single user."""

    async def test_get_user_authenticated(self, client, user_token):
        """Test getting a user when authenticated."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.get("/api/users/1", headers=headers)

        assert response.status_code == 200
        user = response.json()
        assert user["id"] == 1
        assert user["username"] == "admin"

    async def test_get_user_not_found(self, client, user_token):
        """Test getting a non-existent user."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.get("/api/users/99999", headers=headers)

        assert response.status_code == 404


@pytest.mark.asyncio
class TestUpdateUser:
    """Test user updates."""

    async def test_update_user_email(self, client, user_token):
        """Test updating user email."""
        headers = {"Authorization": f"Bearer {user_token}"}

        # Update email
        response = await client.put(
            "/api/users/2",  # john
            headers=headers,
            json={"email": "john_new@example.com"}
        )

        assert response.status_code == 200
        user = response.json()
        assert user["email"] == "john_new@example.com"

        # Restore original
        await client.put(
            "/api/users/2",
            headers=headers,
            json={"email": "john@example.com"}
        )

    async def test_update_user_password(self, client, user_token):
        """Test updating user password."""
        headers = {"Authorization": f"Bearer {user_token}"}

        response = await client.put(
            "/api/users/2",
            headers=headers,
            json={"password": "newpassword123"}
        )

        assert response.status_code == 200

        # Verify new password works
        login_response = await client.post(
            "/api/login",
            data={"username": "john", "password": "newpassword123"}
        )
        assert login_response.status_code == 200

        # Restore original password
        await client.put(
            "/api/users/2",
            headers=headers,
            json={"password": "password123"}
        )


@pytest.mark.asyncio
class TestDeleteUser:
    """Test user deletion."""

    async def test_delete_user(self, client, admin_token):
        """Test deleting a user."""
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create a user to delete
        create_response = await client.post(
            "/api/register",
            json={
                "username": "to_delete",
                "email": "delete@test.com",
                "password": "test123"
            }
        )
        user_id = create_response.json()["id"]

        # Delete the user
        response = await client.delete(
            f"/api/users/{user_id}",
            headers=headers
        )

        assert response.status_code == 200

    async def test_delete_user_not_found(self, client, admin_token):
        """Test deleting a non-existent user."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = await client.delete(
            "/api/users/99999",
            headers=headers
        )

        assert response.status_code == 404


@pytest.mark.asyncio
class TestLegacyAPI:
    """Test legacy API v1 endpoints."""

    async def test_legacy_list_users_no_auth(self, client):
        """Test that legacy API doesn't require auth."""
        response = await client.get("/api/v1/users")

        assert response.status_code == 200
        users = response.json()
        assert len(users) >= 1

    async def test_legacy_exposes_password_hash(self, client):
        """Test that legacy API exposes password hashes."""
        response = await client.get("/api/v1/users/1")

        user = response.json()
        assert "password_hash" in user
        assert user["password_hash"].startswith("$1$")

    async def test_legacy_get_user(self, client):
        """Test getting a user from legacy API."""
        response = await client.get("/api/v1/users/1")

        assert response.status_code == 200
        user = response.json()
        assert user["username"] == "admin"
