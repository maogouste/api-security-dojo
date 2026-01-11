"""
V03 - Excessive Data Exposure
OWASP API3:2023

Tests that verify excessive data is returned in API responses.
"""

import pytest


class TestExcessiveDataExposure:
    """Test cases for Excessive Data Exposure vulnerability."""

    def test_user_response_exposes_ssn(self, client, auth_headers):
        """
        VULNERABILITY: User response contains SSN.
        """
        response = client.get("/api/users/1", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: SSN should never be exposed
        assert "ssn" in data
        assert data["ssn"] == "123-45-6789"

    def test_user_response_exposes_credit_card(self, client, auth_headers):
        """
        VULNERABILITY: User response contains credit card number.
        """
        response = client.get("/api/users/1", headers=auth_headers)

        data = response.json()

        # VULNERABLE: Credit card should never be exposed
        assert "credit_card" in data
        assert "4111" in data["credit_card"]

    def test_user_response_exposes_secret_note(self, client, auth_headers):
        """
        VULNERABILITY: User response contains secret notes with flag.
        """
        response = client.get("/api/users/1", headers=auth_headers)

        data = response.json()

        # VULNERABLE: Secret notes exposed
        assert "secret_note" in data
        assert "VULNAPI{bola_user_data_exposed}" in data["secret_note"]

    def test_user_response_exposes_api_key(self, client, auth_headers):
        """
        VULNERABILITY: User response contains API keys.
        """
        response = client.get("/api/users/1", headers=auth_headers)

        data = response.json()

        # VULNERABLE: API keys should never be exposed
        assert "api_key" in data
        assert data["api_key"] == "admin-api-key-12345"

    def test_product_exposes_internal_notes(self, client):
        """
        VULNERABILITY: Product response contains internal notes.
        """
        response = client.get("/api/products/1")

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: Internal notes should not be exposed
        assert "internal_notes" in data
        assert "VULNAPI{exposure_internal_data_leak}" in data["internal_notes"]

    def test_product_exposes_supplier_cost(self, client):
        """
        VULNERABILITY: Product response contains supplier cost.
        """
        response = client.get("/api/products/1")

        data = response.json()

        # VULNERABLE: Supplier cost is business-sensitive
        assert "supplier_cost" in data
        assert data["supplier_cost"] == 850.0

    def test_list_users_exposes_all_sensitive_data(self, client, auth_headers):
        """
        VULNERABILITY: Listing users exposes everyone's sensitive data.
        """
        response = client.get("/api/users", headers=auth_headers)

        users = response.json()

        # All users have sensitive data exposed
        for user in users:
            assert "ssn" in user
            assert "credit_card" in user
            assert "secret_note" in user

    def test_me_endpoint_exposes_sensitive_data(self, client, user_token):
        """
        VULNERABILITY: /me endpoint returns too much data.
        """
        headers = {"Authorization": f"Bearer {user_token}"}
        response = client.get("/api/me", headers=headers)

        data = response.json()

        # Even own profile exposes sensitive fields
        assert "ssn" in data
        assert "credit_card" in data


class TestExcessiveDataSecure:
    """These tests would pass with proper data filtering."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_user_response_no_sensitive_data(self, client, auth_headers):
        """User response should not contain sensitive data."""
        response = client.get("/api/users/1", headers=auth_headers)
        data = response.json()
        assert "ssn" not in data
        assert "credit_card" not in data
        assert "secret_note" not in data
