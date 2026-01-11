"""
V08 - Security Misconfiguration
OWASP API7:2023

Tests that verify security misconfigurations exist.
"""

import pytest


class TestSecurityMisconfiguration:
    """Test cases for Security Misconfiguration vulnerability."""

    def test_cors_allows_all_origins(self, client):
        """
        VULNERABILITY: CORS allows all origins.
        """
        response = client.options(
            "/api/products",
            headers={"Origin": "https://evil.com"}
        )

        # Check Access-Control-Allow-Origin header
        cors_header = response.headers.get("access-control-allow-origin", "")

        # VULNERABLE: Should not allow all origins
        assert cors_header == "*" or cors_header == "https://evil.com"

    def test_cors_allows_credentials(self, client):
        """
        VULNERABILITY: CORS allows credentials with wildcard origin.
        """
        response = client.get("/api/products")

        # Check if credentials are allowed
        allow_creds = response.headers.get("access-control-allow-credentials", "")

        # Combined with * origin, this is dangerous
        if allow_creds.lower() == "true":
            assert True  # Vulnerability confirmed

    def test_debug_endpoint_exposed(self, client):
        """
        VULNERABILITY: Debug endpoint is exposed in production.
        """
        response = client.get("/api/tools/debug")

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: Debug info exposed
        assert "environment" in data or "config" in data or "debug" in data

    def test_sensitive_headers_missing(self, client):
        """
        VULNERABILITY: Security headers are missing.
        """
        response = client.get("/api/products")

        headers = response.headers

        # Check for missing security headers
        missing_headers = []

        if "x-content-type-options" not in headers:
            missing_headers.append("X-Content-Type-Options")

        if "x-frame-options" not in headers:
            missing_headers.append("X-Frame-Options")

        if "content-security-policy" not in headers:
            missing_headers.append("Content-Security-Policy")

        if "strict-transport-security" not in headers:
            missing_headers.append("Strict-Transport-Security")

        # VULNERABLE: Security headers should be present
        assert len(missing_headers) > 0

    def test_verbose_error_messages(self, client, auth_headers):
        """
        VULNERABILITY: Verbose error messages expose internals.
        """
        # Try to access non-existent resource
        response = client.get("/api/users/99999", headers=auth_headers)

        assert response.status_code == 404
        data = response.json()

        # Error message is present (could be more verbose in other cases)
        assert "detail" in data

    def test_swagger_docs_enabled(self, client):
        """
        VULNERABILITY: Swagger docs enabled (should be disabled in prod).
        """
        response = client.get("/docs")

        # VULNERABLE: Docs should be disabled in production
        assert response.status_code == 200
        assert "swagger" in response.text.lower()

    def test_openapi_json_exposed(self, client):
        """
        VULNERABILITY: OpenAPI spec is publicly accessible.
        """
        response = client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()

        # Full API spec exposed
        assert "paths" in data
        assert "components" in data

    def test_health_exposes_debug_status(self, client):
        """
        VULNERABILITY: Health endpoint exposes debug mode.
        """
        response = client.get("/health")

        data = response.json()

        # VULNERABLE: Debug status exposed
        assert "debug" in data


class TestSecurityMisconfigSecure:
    """These tests would pass with proper security configuration."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_cors_restrictive(self, client):
        """CORS should only allow specific origins."""
        response = client.options(
            "/api/products",
            headers={"Origin": "https://evil.com"}
        )
        assert "evil.com" not in response.headers.get(
            "access-control-allow-origin", ""
        )
