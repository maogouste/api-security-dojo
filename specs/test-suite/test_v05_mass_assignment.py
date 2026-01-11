"""
V05 - Mass Assignment
OWASP API6:2023

Tests that verify mass assignment vulnerability exists.
Users can modify fields they shouldn't have access to.
"""

import pytest


class TestMassAssignment:
    """Test cases for Mass Assignment vulnerability."""

    def test_can_update_own_email(self, client, user_token):
        """User can update their own email (legitimate)."""
        headers = {"Authorization": f"Bearer {user_token}"}

        response = client.put(
            "/api/users/2",  # john's id
            headers=headers,
            json={"email": "john_updated@example.com"}
        )

        assert response.status_code == 200

    def test_mass_assignment_change_role(self, client):
        """
        VULNERABILITY: User can change their own role to admin.
        """
        # Create a new user
        response = client.post(
            "/api/register",
            json={
                "username": "mass_test_user",
                "email": "mass_test@example.com",
                "password": "test123"
            }
        )
        assert response.status_code == 200
        user_id = response.json()["id"]

        # Login as this user
        response = client.post(
            "/api/login",
            data={"username": "mass_test_user", "password": "test123"}
        )
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # VULNERABILITY: Try to change role to admin
        response = client.put(
            f"/api/users/{user_id}",
            headers=headers,
            json={"role": "admin"}
        )

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: Role was changed!
        assert data["role"] == "admin"

    def test_mass_assignment_activate_account(self, client, admin_headers):
        """
        VULNERABILITY: User can change is_active status.
        """
        # First deactivate a user (as admin)
        client.put(
            "/api/users/4",  # bob
            headers=admin_headers,
            json={"is_active": False}
        )

        # Login as another user
        response = client.post(
            "/api/login",
            data={"username": "john", "password": "password123"}
        )
        john_token = response.json()["access_token"]
        john_headers = {"Authorization": f"Bearer {john_token}"}

        # VULNERABILITY: John can reactivate bob
        response = client.put(
            "/api/users/4",
            headers=john_headers,
            json={"is_active": True}
        )

        assert response.status_code == 200

        # Restore bob's status
        client.put(
            "/api/users/4",
            headers=admin_headers,
            json={"is_active": True}
        )

    def test_mass_assignment_set_api_key(self, client, user_token):
        """
        VULNERABILITY: User can set their own API key.
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        response = client.put(
            "/api/users/2",  # john
            headers=headers,
            json={"api_key": "my-custom-api-key"}
        )

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: API key was set
        assert data["api_key"] == "my-custom-api-key"

    def test_mass_assignment_on_other_user(self, client, user_token):
        """
        VULNERABILITY: Can mass assign on other users too.
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        # Try to make bob an admin
        response = client.put(
            "/api/users/4",  # bob
            headers=headers,
            json={"role": "admin"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "admin"

        # Restore bob's role
        response = client.put(
            "/api/users/4",
            headers=headers,
            json={"role": "user"}
        )


class TestMassAssignmentSecure:
    """These tests would pass with proper input validation."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_cannot_change_role(self, client, user_token):
        """Users should not be able to change their role."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.put(
            "/api/users/2",
            headers=headers,
            json={"role": "admin"}
        )
        # Should either reject or ignore the role field
        assert response.json()["role"] == "user"
