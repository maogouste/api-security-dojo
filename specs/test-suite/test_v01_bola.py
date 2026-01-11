"""
V01 - Broken Object Level Authorization (BOLA)
OWASP API1:2023

Tests that verify the BOLA vulnerability exists and is exploitable.
An authenticated user should be able to access other users' data.
"""

import pytest


class TestBOLA:
    """Test cases for Broken Object Level Authorization."""

    def test_can_access_own_profile(self, client, user_token):
        """User can access their own profile."""
        headers = {"Authorization": f"Bearer {user_token}"}

        # Get user info from token (user john has id 2)
        response = client.get("/api/users/2", headers=headers)

        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "john"

    def test_bola_access_other_user_data(self, client, user_token):
        """
        VULNERABILITY: User can access another user's data.

        Exploit: Authenticated as 'john', access admin's data (id=1)
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        # Try to access admin user (id=1) while authenticated as john
        response = client.get("/api/users/1", headers=headers)

        # VULNERABLE: Should be 403, but returns 200
        assert response.status_code == 200
        data = response.json()

        # Verify we got admin's sensitive data
        assert data["username"] == "admin"
        assert data["email"] == "admin@vulnapi.local"
        assert "ssn" in data
        assert "credit_card" in data

        # Flag should be in secret_note
        assert "VULNAPI{bola_user_data_exposed}" in data.get("secret_note", "")

    def test_bola_access_all_users(self, client, user_token):
        """
        VULNERABILITY: User can list all users with sensitive data.
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        response = client.get("/api/users", headers=headers)

        assert response.status_code == 200
        users = response.json()

        # Should return multiple users
        assert len(users) >= 3

        # All users should have sensitive data exposed
        for user in users:
            assert "ssn" in user
            assert "credit_card" in user

    def test_bola_update_other_user(self, client, user_token):
        """
        VULNERABILITY: User can update another user's data.
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        # Try to update bob's email (id=4)
        response = client.put(
            "/api/users/4",
            headers=headers,
            json={"email": "hacked@example.com"}
        )

        # VULNERABLE: Should be 403, but allows update
        assert response.status_code == 200

    def test_bola_delete_other_user(self, client, user_token):
        """
        VULNERABILITY: User could delete another user.

        Note: We don't actually delete to preserve test data,
        but verify the endpoint doesn't reject unauthorized requests.
        """
        headers = {"Authorization": f"Bearer {user_token}"}

        # Create a temporary user first
        response = client.post(
            "/api/register",
            json={
                "username": "temp_bola_test",
                "email": "temp_bola@test.com",
                "password": "test123"
            }
        )

        if response.status_code == 200:
            temp_user_id = response.json()["id"]

            # Now try to delete as john (not the owner)
            response = client.delete(
                f"/api/users/{temp_user_id}",
                headers=headers
            )

            # VULNERABLE: Should be 403
            assert response.status_code == 200


class TestBOLASecure:
    """These tests would pass if the API was properly secured."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_cannot_access_other_user_data(self, client, user_token):
        """In a secure API, accessing other users should be forbidden."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.get("/api/users/1", headers=headers)
        assert response.status_code == 403
