"""
V09 - Improper Assets Management
OWASP API9:2023

Tests that verify old API versions are still accessible.
"""

import pytest


class TestImproperAssetsManagement:
    """Test cases for Improper Assets Management vulnerability."""

    def test_legacy_api_exists(self, client):
        """
        VULNERABILITY: Legacy API v1 is still accessible.
        """
        response = client.get("/api/v1/users")

        # VULNERABLE: Old API should be deprecated/removed
        assert response.status_code == 200

    def test_legacy_api_no_auth(self, client):
        """
        VULNERABILITY: Legacy API doesn't require authentication.
        """
        # No auth headers
        response = client.get("/api/v1/users")

        assert response.status_code == 200
        users = response.json()

        # Returns user data without authentication
        assert len(users) >= 1

    def test_legacy_api_exposes_password_hash(self, client):
        """
        VULNERABILITY: Legacy API exposes password hashes.
        """
        response = client.get("/api/v1/users")

        users = response.json()

        # VULNERABLE: Password hashes exposed!
        for user in users:
            assert "password_hash" in user
            # Hash starts with $1$ (MD5-crypt)
            assert user["password_hash"].startswith("$1$")

    def test_legacy_api_exposes_all_sensitive_data(self, client):
        """
        VULNERABILITY: Legacy API exposes all sensitive fields.
        """
        response = client.get("/api/v1/users/1")

        assert response.status_code == 200
        user = response.json()

        # All sensitive fields exposed
        assert "password_hash" in user
        assert "ssn" in user
        assert "credit_card" in user
        assert "api_key" in user

    def test_legacy_api_get_specific_user(self, client):
        """
        VULNERABILITY: Can get any user without auth.
        """
        response = client.get("/api/v1/users/5")  # service account

        assert response.status_code == 200
        user = response.json()

        # Service account data exposed
        assert user["username"] == "service_account"
        assert user["role"] == "superadmin"
        assert "VULNAPI{jwt_weak_secret_cracked}" in user.get("api_key", "")

    def test_legacy_vs_current_api_comparison(self, client, auth_headers):
        """
        Compare legacy API with current API to show differences.
        """
        # Legacy API (no auth)
        legacy_response = client.get("/api/v1/users/1")
        legacy_user = legacy_response.json()

        # Current API (with auth)
        current_response = client.get("/api/users/1", headers=auth_headers)
        current_user = current_response.json()

        # Legacy has more fields
        assert "password_hash" in legacy_user
        assert "password_hash" not in current_user

        # Legacy has timestamps that current might not expose the same way
        assert "updated_at" in legacy_user


class TestImproperAssetsSecure:
    """These tests would pass with proper API versioning."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_legacy_api_removed(self, client):
        """Legacy API should be removed or require auth."""
        response = client.get("/api/v1/users")
        assert response.status_code in [401, 404]
