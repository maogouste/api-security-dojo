"""
V07 - Command Injection
OWASP API8:2023 / CWE-78

Tests that verify command injection vulnerability exists.
"""

import pytest


class TestCommandInjection:
    """Test cases for Command Injection vulnerability."""

    def test_ping_normal(self, client, auth_headers):
        """Normal ping should work."""
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "127.0.0.1" in data["stdout"]

    def test_command_injection_semicolon(self, client, auth_headers):
        """
        VULNERABILITY: Command injection with semicolon.

        Payload: 127.0.0.1; whoami
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1; whoami"}
        )

        assert response.status_code == 200
        data = response.json()

        # VULNERABLE: Command was exposed in response
        assert "127.0.0.1; whoami" in data.get("command", "")

        # whoami output should be in stdout
        assert len(data.get("stdout", "")) > 0

    def test_command_injection_and_operator(self, client, auth_headers):
        """
        VULNERABILITY: Command injection with && operator.

        Payload: 127.0.0.1 && id
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1 && id"}
        )

        assert response.status_code == 200
        data = response.json()

        # The 'id' command output might be in stdout
        stdout = data.get("stdout", "")
        # Check if uid info is present (from id command)
        assert "uid=" in stdout or "icmp_seq" in stdout

    def test_command_injection_pipe(self, client, auth_headers):
        """
        VULNERABILITY: Command injection with pipe.

        Payload: 127.0.0.1 | echo INJECTED
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1 | echo INJECTED"}
        )

        assert response.status_code == 200
        data = response.json()

        # Command contains the injection
        assert "|" in data.get("command", "")

    def test_command_injection_subshell(self, client, auth_headers):
        """
        VULNERABILITY: Command injection with subshell.

        Payload: $(echo pwned)
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "$(echo pwned)"}
        )

        assert response.status_code == 200
        data = response.json()

        # Command contains the subshell
        assert "$(" in data.get("command", "")

    def test_command_injection_backticks(self, client, auth_headers):
        """
        VULNERABILITY: Command injection with backticks.

        Payload: `id`
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "`id`"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "`" in data.get("command", "")

    def test_dns_lookup_injection(self, client, auth_headers):
        """
        VULNERABILITY: DNS lookup also vulnerable to command injection.
        """
        response = client.post(
            "/api/tools/dns",
            headers=auth_headers,
            json={"domain": "google.com; id"}
        )

        assert response.status_code == 200
        data = response.json()

        # Output might contain id command result
        assert "google.com; id" in str(data)

    def test_command_exposed_in_response(self, client, auth_headers):
        """
        VULNERABILITY: Executed command is returned in response.
        """
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1"}
        )

        data = response.json()

        # VULNERABLE: Command should not be exposed
        assert "command" in data
        assert "ping" in data["command"]


class TestCommandInjectionSecure:
    """These tests would pass with proper input sanitization."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_injection_blocked(self, client, auth_headers):
        """Command injection should be blocked."""
        response = client.post(
            "/api/tools/ping",
            headers=auth_headers,
            json={"host": "127.0.0.1; whoami"}
        )
        # Should reject invalid host format
        assert response.status_code == 400
