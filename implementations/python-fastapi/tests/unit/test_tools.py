"""Unit tests for tools endpoints."""

import pytest


@pytest.mark.asyncio
class TestPing:
    """Test ping endpoint."""

    async def test_ping_localhost(self, client, user_token):
        """Test pinging localhost."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.post(
            "/api/tools/ping",
            headers=headers,
            json={"host": "127.0.0.1"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "127.0.0.1" in data["stdout"]

    async def test_ping_no_auth(self, client):
        """Test ping without authentication."""
        response = await client.post(
            "/api/tools/ping",
            json={"host": "127.0.0.1"}
        )

        assert response.status_code == 401


@pytest.mark.asyncio
class TestDNS:
    """Test DNS lookup endpoint."""

    async def test_dns_lookup(self, client, user_token):
        """Test DNS lookup."""
        headers = {"Authorization": f"Bearer {user_token}"}
        response = await client.post(
            "/api/tools/dns",
            headers=headers,
            json={"domain": "localhost"}
        )

        assert response.status_code == 200

    async def test_dns_no_auth(self, client):
        """Test DNS lookup without authentication."""
        response = await client.post(
            "/api/tools/dns",
            json={"domain": "google.com"}
        )

        assert response.status_code == 401


@pytest.mark.asyncio
class TestDebug:
    """Test debug endpoint."""

    async def test_debug_endpoint(self, client):
        """Test that debug endpoint is accessible."""
        response = await client.get("/api/tools/debug")

        assert response.status_code == 200
        data = response.json()
        # Should return some debug info
        assert isinstance(data, dict)


@pytest.mark.asyncio
class TestHeaders:
    """Test headers endpoint."""

    async def test_headers_endpoint(self, client):
        """Test headers info endpoint."""
        response = await client.get("/api/tools/headers")

        assert response.status_code == 200
        data = response.json()
        assert "security_headers" in data or "missing_headers" in data or isinstance(data, dict)
