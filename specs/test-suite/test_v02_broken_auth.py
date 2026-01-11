"""
V02 - Broken Authentication
OWASP API2:2023

Tests that verify authentication vulnerabilities exist.
"""

import pytest
import base64
import json


class TestBrokenAuthentication:
    """Test cases for Broken Authentication vulnerabilities."""

    def test_login_success(self, client):
        """Basic login should work."""
        response = client.post(
            "/api/login",
            data={"username": "admin", "password": "admin123"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_user_enumeration_via_error_messages(self, client):
        """
        VULNERABILITY: Different error messages reveal user existence.
        """
        # Non-existent user
        response1 = client.post(
            "/api/login",
            data={"username": "nonexistent_user_xyz", "password": "wrong"}
        )
        error1 = response1.json().get("detail", "")

        # Existing user, wrong password
        response2 = client.post(
            "/api/login",
            data={"username": "admin", "password": "wrongpassword"}
        )
        error2 = response2.json().get("detail", "")

        # VULNERABLE: Error messages should be the same
        # but they reveal whether user exists
        assert error1 != error2
        assert "not found" in error1.lower() or "incorrect" in error2.lower()

    def test_weak_jwt_secret(self, client):
        """
        VULNERABILITY: JWT uses a weak/guessable secret.

        The secret 'intentionally-weak-secret' can be cracked.
        """
        response = client.post(
            "/api/login",
            data={"username": "admin", "password": "admin123"}
        )

        token = response.json()["access_token"]

        # Decode JWT payload (without verification)
        parts = token.split(".")
        assert len(parts) == 3

        # Decode payload
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # VULNERABILITY: Role is included in token (can be modified if secret is known)
        assert "role" in payload
        assert "user_id" in payload

    def test_jwt_contains_sensitive_info(self, client):
        """
        VULNERABILITY: JWT payload contains role that could be tampered with.
        """
        response = client.post(
            "/api/login",
            data={"username": "john", "password": "password123"}
        )

        token = response.json()["access_token"]
        parts = token.split(".")
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Role in token can be modified if secret is compromised
        assert payload["role"] == "user"
        assert payload["user_id"] == 2

    def test_no_password_complexity(self, client):
        """
        VULNERABILITY: No password strength requirements.
        """
        # Should be able to register with weak password
        response = client.post(
            "/api/register",
            json={
                "username": "weakpass_test",
                "email": "weakpass@test.com",
                "password": "a"  # Single character password
            }
        )

        # VULNERABLE: Should reject weak passwords
        assert response.status_code == 200

    def test_token_in_response_body(self, client):
        """
        VULNERABILITY: Login returns sensitive info in response.
        """
        response = client.post(
            "/api/login",
            data={"username": "admin", "password": "admin123"}
        )

        data = response.json()

        # VULNERABLE: Exposes user_id and role in response
        assert "user_id" in data
        assert "role" in data


class TestBrokenAuthSecure:
    """These tests would pass if authentication was properly implemented."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_consistent_error_messages(self, client):
        """Error messages should not reveal user existence."""
        response1 = client.post(
            "/api/login",
            data={"username": "nonexistent", "password": "wrong"}
        )
        response2 = client.post(
            "/api/login",
            data={"username": "admin", "password": "wrong"}
        )
        assert response1.json()["detail"] == response2.json()["detail"]
