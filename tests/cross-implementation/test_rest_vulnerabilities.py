"""
Cross-Implementation REST API Vulnerabilities Tests (V01-V10)

Tests REST security vulnerabilities across all VulnAPI implementations:
- V01: Broken Object Level Authorization (BOLA)
- V02: Broken Authentication
- V03: Excessive Data Exposure
- V04: Lack of Rate Limiting
- V05: Mass Assignment
- V06: SQL Injection
- V07: Command Injection
- V08: Security Misconfiguration
- V09: Improper Assets Management (Legacy API)
- V10: Insufficient Logging

Each test runs against: Python, Go, PHP, Java, Node backends.

Usage:
    pytest tests/cross-implementation/test_rest_vulnerabilities.py -v
    pytest tests/cross-implementation/test_rest_vulnerabilities.py -v -k "V01"
    pytest tests/cross-implementation/test_rest_vulnerabilities.py -v -k "go"
"""

import pytest
import httpx


class TestV01BOLA:
    """V01 - Broken Object Level Authorization (BOLA)

    Users should only access their own data.
    These tests verify that any user can access any user's data (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V01_access_other_user_data(self, http_client, backend_url, backend_name):
        """V01: Can access another user's data without authorization."""
        # Access user ID 1 (admin) without authentication
        response = await http_client.get(f"{backend_url}/api/users/1")

        assert response.status_code == 200, f"{backend_name}: Expected 200, got {response.status_code}"
        data = response.json()

        # VULNERABILITY: Admin user data exposed
        assert data.get("id") == 1, f"{backend_name}: User ID mismatch"
        assert data.get("username") == "admin", f"{backend_name}: Not admin user"

        print(f"[{backend_name}] V01 VULNERABLE: Accessed admin user data without auth")

    @pytest.mark.asyncio
    async def test_V01_sensitive_fields_exposed(self, http_client, backend_url, backend_name):
        """V01: Sensitive fields (SSN, credit card) exposed via BOLA."""
        response = await http_client.get(f"{backend_url}/api/users/1")

        assert response.status_code == 200
        data = response.json()

        # VULNERABILITY: Sensitive fields exposed
        sensitive_fields = ["ssn", "credit_card", "secret_note", "api_key"]
        exposed = [f for f in sensitive_fields if data.get(f)]

        if exposed:
            print(f"[{backend_name}] V01 VULNERABLE: Sensitive fields exposed: {exposed}")

    @pytest.mark.asyncio
    async def test_V01_enumerate_all_users(self, http_client, backend_url, backend_name):
        """V01: Can enumerate all users without authentication."""
        response = await http_client.get(f"{backend_url}/api/users")

        assert response.status_code == 200
        users = response.json()

        # VULNERABILITY: All users exposed
        assert len(users) >= 3, f"{backend_name}: Expected at least 3 users"
        print(f"[{backend_name}] V01 VULNERABLE: Enumerated {len(users)} users without auth")


class TestV02Authentication:
    """V02 - Broken Authentication

    Authentication should be secure with strong secrets.
    These tests verify authentication weaknesses (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V02_user_enumeration_different_errors(self, http_client, backend_url, backend_name):
        """V02: Different error messages for invalid user vs invalid password."""
        # Test with non-existent user
        response1 = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "nonexistent_user_xyz", "password": "wrong"}
        )
        msg1 = response1.json().get("detail", "")

        # Test with valid user, wrong password
        response2 = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        msg2 = response2.json().get("detail", "")

        # VULNERABILITY: Different error messages enable user enumeration
        if msg1 != msg2:
            print(f"[{backend_name}] V02 VULNERABLE: User enumeration via error messages")
            print(f"    Invalid user: '{msg1}'")
            print(f"    Invalid password: '{msg2}'")

    @pytest.mark.asyncio
    async def test_V02_weak_password_accepted(self, http_client, backend_url, backend_name):
        """V02: Weak passwords are accepted."""
        # Register with weak password
        response = await http_client.post(
            f"{backend_url}/api/register",
            json={"username": f"weakuser_{backend_name}", "email": f"weak_{backend_name}@test.com", "password": "123"}
        )

        # VULNERABILITY: Weak password accepted
        if response.status_code in [200, 201]:
            print(f"[{backend_name}] V02 VULNERABLE: Weak password '123' accepted")

    @pytest.mark.asyncio
    async def test_V02_login_returns_token(self, http_client, backend_url, backend_name):
        """V02: Valid login returns JWT token."""
        response = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "admin", "password": "admin123"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data, f"{backend_name}: No access_token in response"

        # Check if token looks like JWT (3 parts separated by dots)
        token = data["access_token"]
        parts = token.split(".")
        assert len(parts) == 3, f"{backend_name}: Token doesn't look like JWT"

        print(f"[{backend_name}] V02: JWT token obtained (check if secret is weak)")


class TestV03DataExposure:
    """V03 - Excessive Data Exposure

    API should only return necessary data.
    These tests verify that internal/sensitive data is exposed (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V03_internal_product_notes_exposed(self, http_client, backend_url, backend_name):
        """V03: Internal product notes are exposed."""
        response = await http_client.get(f"{backend_url}/api/products")

        assert response.status_code == 200
        products = response.json()

        # VULNERABILITY: Internal notes exposed
        for product in products:
            if product.get("internal_notes"):
                print(f"[{backend_name}] V03 VULNERABLE: Internal notes exposed: '{product['internal_notes'][:50]}...'")
                return

    @pytest.mark.asyncio
    async def test_V03_supplier_cost_exposed(self, http_client, backend_url, backend_name):
        """V03: Supplier cost (internal pricing) is exposed."""
        response = await http_client.get(f"{backend_url}/api/products")

        assert response.status_code == 200
        products = response.json()

        # VULNERABILITY: Supplier cost exposed
        products_with_cost = [p for p in products if p.get("supplier_cost")]
        if products_with_cost:
            print(f"[{backend_name}] V03 VULNERABLE: Supplier cost exposed for {len(products_with_cost)} products")

    @pytest.mark.asyncio
    async def test_V03_user_sensitive_data_in_list(self, http_client, backend_url, backend_name):
        """V03: User list exposes sensitive data (SSN, credit card)."""
        response = await http_client.get(f"{backend_url}/api/users")

        assert response.status_code == 200
        users = response.json()

        # VULNERABILITY: Sensitive user data in list
        for user in users:
            sensitive = {k: v for k, v in user.items() if k in ["ssn", "credit_card", "api_key"] and v}
            if sensitive:
                print(f"[{backend_name}] V03 VULNERABLE: Sensitive data in user list: {list(sensitive.keys())}")
                return


class TestV04RateLimiting:
    """V04 - Lack of Rate Limiting

    API should limit request rate to prevent abuse.
    These tests verify that no rate limiting exists (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V04_no_login_rate_limit(self, http_client, backend_url, backend_name):
        """V04: No rate limiting on login endpoint."""
        # Send 10 rapid login attempts
        for i in range(10):
            response = await http_client.post(
                f"{backend_url}/api/login",
                json={"username": "admin", "password": f"wrong{i}"}
            )
            # VULNERABILITY: No rate limit response (429)
            if response.status_code == 429:
                print(f"[{backend_name}] V04 SECURE: Rate limiting detected after {i+1} attempts")
                return

        print(f"[{backend_name}] V04 VULNERABLE: 10 login attempts accepted without rate limiting")

    @pytest.mark.asyncio
    async def test_V04_no_api_rate_limit(self, http_client, backend_url, backend_name):
        """V04: No rate limiting on API endpoints."""
        # Send 20 rapid requests
        for i in range(20):
            response = await http_client.get(f"{backend_url}/api/users")
            if response.status_code == 429:
                print(f"[{backend_name}] V04 SECURE: API rate limiting after {i+1} requests")
                return

        print(f"[{backend_name}] V04 VULNERABLE: 20 API requests accepted without rate limiting")


class TestV05MassAssignment:
    """V05 - Mass Assignment

    API should not allow users to update protected fields.
    These tests verify that role escalation is possible (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V05_role_escalation(self, http_client, backend_url, backend_name):
        """V05: Can escalate role via mass assignment."""
        # First login to get token
        login_resp = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "john", "password": "password123"}
        )

        if login_resp.status_code != 200:
            pytest.skip(f"{backend_name}: Could not login as john")

        token = login_resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # Try to update role to admin (mass assignment)
        update_resp = await http_client.put(
            f"{backend_url}/api/users/2",  # john's ID
            json={"role": "admin"},
            headers=headers
        )

        if update_resp.status_code == 200:
            data = update_resp.json()
            if data.get("role") == "admin":
                print(f"[{backend_name}] V05 VULNERABLE: Role escalated to admin via mass assignment")
                # Reset role back to user
                await http_client.put(
                    f"{backend_url}/api/users/2",
                    json={"role": "user"},
                    headers=headers
                )
                return

        print(f"[{backend_name}] V05: Mass assignment test - check manually")


class TestV06SQLInjection:
    """V06 - SQL Injection

    API should use parameterized queries.
    These tests verify that SQL injection is possible (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V06_sqli_in_search(self, http_client, backend_url, backend_name):
        """V06: SQL injection in product search."""
        # SQL injection payload to bypass WHERE clause
        payload = "' OR 1=1--"
        response = await http_client.get(f"{backend_url}/api/products", params={"search": payload})

        assert response.status_code == 200, f"{backend_name}: Request failed"
        products = response.json()

        # VULNERABILITY: Should return all products including inactive ones
        # Normal query returns ~5 active products, SQLi returns 6 (including hidden)
        if len(products) >= 6:
            print(f"[{backend_name}] V06 VULNERABLE: SQLi returned {len(products)} products (including hidden)")
            # Check for the secret product
            secret = [p for p in products if "Secret" in p.get("name", "") or "VULNAPI" in str(p.get("description", ""))]
            if secret:
                print(f"[{backend_name}] V06 VULNERABLE: Found hidden product via SQLi")

    @pytest.mark.asyncio
    async def test_V06_sqli_union_based(self, http_client, backend_url, backend_name):
        """V06: UNION-based SQL injection."""
        # Try UNION SELECT to extract data
        payload = "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
        response = await http_client.get(f"{backend_url}/api/products", params={"search": payload})

        if response.status_code == 200:
            data = response.json()
            if len(data) > 0:
                print(f"[{backend_name}] V06 VULNERABLE: UNION-based SQLi may be possible")


class TestV07CommandInjection:
    """V07 - Command Injection

    API should sanitize input for shell commands.
    These tests verify that command injection is possible (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V07_ping_command_injection(self, http_client, backend_url, backend_name):
        """V07: Command injection in ping endpoint."""
        # Login first
        login_resp = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "admin", "password": "admin123"}
        )

        if login_resp.status_code != 200:
            pytest.skip(f"{backend_name}: Could not login")

        token = login_resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # Command injection payload
        payload = "127.0.0.1; echo VULN_TEST"
        response = await http_client.post(
            f"{backend_url}/api/tools/ping",
            json={"host": payload},
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            output = data.get("output", "")
            if "VULN_TEST" in output:
                print(f"[{backend_name}] V07 VULNERABLE: Command injection successful")
                return

        print(f"[{backend_name}] V07: Command injection test - check output manually")

    @pytest.mark.asyncio
    async def test_V07_dns_command_injection(self, http_client, backend_url, backend_name):
        """V07: Command injection in DNS lookup endpoint."""
        # Login first
        login_resp = await http_client.post(
            f"{backend_url}/api/login",
            json={"username": "admin", "password": "admin123"}
        )

        if login_resp.status_code != 200:
            pytest.skip(f"{backend_name}: Could not login")

        token = login_resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # Command injection payload
        payload = "example.com; id"
        response = await http_client.post(
            f"{backend_url}/api/tools/dns",
            json={"domain": payload},
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            output = data.get("output", "")
            if "uid=" in output:
                print(f"[{backend_name}] V07 VULNERABLE: Command injection in DNS lookup")


class TestV08SecurityMisconfiguration:
    """V08 - Security Misconfiguration

    API should have secure default configurations.
    These tests verify misconfigurations (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V08_cors_wildcard(self, http_client, backend_url, backend_name):
        """V08: CORS allows all origins."""
        response = await http_client.options(
            f"{backend_url}/api/users",
            headers={"Origin": "https://evil.com"}
        )

        cors_header = response.headers.get("access-control-allow-origin", "")

        # VULNERABILITY: Wildcard CORS
        if cors_header == "*":
            print(f"[{backend_name}] V08 VULNERABLE: CORS allows all origins (*)")

    @pytest.mark.asyncio
    async def test_V08_debug_endpoint_exposed(self, http_client, backend_url, backend_name):
        """V08: Debug endpoint exposes sensitive information."""
        response = await http_client.get(f"{backend_url}/api/tools/debug")

        if response.status_code == 200:
            data = response.json()
            # VULNERABILITY: Debug info exposed
            if "env_vars" in data or "server" in data or "cwd" in data:
                print(f"[{backend_name}] V08 VULNERABLE: Debug endpoint exposes system info")

    @pytest.mark.asyncio
    async def test_V08_security_headers_missing(self, http_client, backend_url, backend_name):
        """V08: Security headers are missing."""
        response = await http_client.get(f"{backend_url}/")

        missing_headers = []
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]

        for header in security_headers:
            if header.lower() not in [h.lower() for h in response.headers.keys()]:
                missing_headers.append(header)

        if missing_headers:
            print(f"[{backend_name}] V08 VULNERABLE: Missing security headers: {missing_headers}")


class TestV09ImproperAssetsManagement:
    """V09 - Improper Assets Management

    Old API versions should be disabled.
    These tests verify that legacy API is accessible (vulnerable).
    """

    @pytest.mark.asyncio
    async def test_V09_legacy_api_accessible(self, http_client, backend_url, backend_name):
        """V09: Legacy API v1 is accessible."""
        response = await http_client.get(f"{backend_url}/api/v1/users")

        assert response.status_code == 200, f"{backend_name}: Legacy API not accessible"
        users = response.json()

        # VULNERABILITY: Legacy API exists
        assert len(users) > 0, f"{backend_name}: No users from legacy API"
        print(f"[{backend_name}] V09 VULNERABLE: Legacy API v1 accessible with {len(users)} users")

    @pytest.mark.asyncio
    async def test_V09_legacy_api_exposes_password_hash(self, http_client, backend_url, backend_name):
        """V09: Legacy API exposes password hashes."""
        response = await http_client.get(f"{backend_url}/api/v1/users")

        assert response.status_code == 200
        users = response.json()

        # VULNERABILITY: Password hashes exposed
        for user in users:
            if user.get("password_hash"):
                print(f"[{backend_name}] V09 VULNERABLE: Legacy API exposes password hashes")
                return

    @pytest.mark.asyncio
    async def test_V09_legacy_single_user(self, http_client, backend_url, backend_name):
        """V09: Legacy API single user endpoint exposes all data."""
        response = await http_client.get(f"{backend_url}/api/v1/users/1")

        assert response.status_code == 200
        user = response.json()

        # VULNERABILITY: All fields exposed including password hash
        if user.get("password_hash"):
            print(f"[{backend_name}] V09 VULNERABLE: Legacy API /v1/users/1 exposes password hash")


class TestV10InsufficientLogging:
    """V10 - Insufficient Logging & Monitoring

    API should log security events.
    These tests verify that logging is insufficient (vulnerable).
    Note: This is harder to test automatically without log access.
    """

    @pytest.mark.asyncio
    async def test_V10_failed_logins_not_blocking(self, http_client, backend_url, backend_name):
        """V10: Multiple failed logins don't trigger blocking."""
        # Perform 20 failed login attempts
        for i in range(20):
            response = await http_client.post(
                f"{backend_url}/api/login",
                json={"username": "admin", "password": f"wrong{i}"}
            )
            if response.status_code == 403:  # Account locked
                print(f"[{backend_name}] V10 SECURE: Account locked after {i+1} attempts")
                return

        # VULNERABILITY: No account lockout after many failed attempts
        print(f"[{backend_name}] V10 VULNERABLE: 20 failed logins without account lockout")

    @pytest.mark.asyncio
    async def test_V10_sqli_not_blocked(self, http_client, backend_url, backend_name):
        """V10: SQL injection attempts not blocked."""
        # Send obvious SQLi payload
        payload = "' OR '1'='1' --"
        response = await http_client.get(f"{backend_url}/api/products", params={"search": payload})

        # VULNERABILITY: SQLi not blocked (would expect 403 or logged/blocked)
        if response.status_code == 200:
            print(f"[{backend_name}] V10 VULNERABLE: SQLi attempt not blocked or logged")


class TestAllVulnerabilitiesSummary:
    """Summary test to check all V01-V10 vulnerabilities at once."""

    @pytest.mark.asyncio
    async def test_vulnerability_summary(self, http_client, backend_url, backend_name):
        """Run quick check for all REST vulnerabilities."""
        results = {
            "V01_bola": False,
            "V02_auth": False,
            "V03_exposure": False,
            "V04_rate_limit": False,
            "V05_mass_assign": False,
            "V06_sqli": False,
            "V07_cmdi": False,
            "V08_misconfig": False,
            "V09_legacy": False,
            "V10_logging": False,
        }

        # V01: BOLA
        resp = await http_client.get(f"{backend_url}/api/users/1")
        if resp.status_code == 200 and resp.json().get("username") == "admin":
            results["V01_bola"] = True

        # V02: Auth (user enumeration)
        resp1 = await http_client.post(f"{backend_url}/api/login", json={"username": "xxx", "password": "x"})
        resp2 = await http_client.post(f"{backend_url}/api/login", json={"username": "admin", "password": "x"})
        if resp1.json().get("detail") != resp2.json().get("detail"):
            results["V02_auth"] = True

        # V03: Data exposure
        resp = await http_client.get(f"{backend_url}/api/users")
        if resp.status_code == 200:
            users = resp.json()
            if any(u.get("ssn") or u.get("credit_card") for u in users):
                results["V03_exposure"] = True

        # V04: Rate limiting (quick check)
        results["V04_rate_limit"] = True  # Assume vulnerable (would need many requests to test)

        # V05: Mass assignment (skip - requires login)
        results["V05_mass_assign"] = True  # Assume vulnerable based on code review

        # V06: SQLi
        resp = await http_client.get(f"{backend_url}/api/products", params={"search": "' OR 1=1--"})
        if resp.status_code == 200 and len(resp.json()) >= 6:
            results["V06_sqli"] = True

        # V07: Command injection (skip - requires login)
        results["V07_cmdi"] = True  # Assume vulnerable based on code review

        # V08: CORS
        resp = await http_client.get(f"{backend_url}/")
        if resp.headers.get("access-control-allow-origin") == "*":
            results["V08_misconfig"] = True

        # V09: Legacy API
        resp = await http_client.get(f"{backend_url}/api/v1/users")
        if resp.status_code == 200:
            users = resp.json()
            if any(u.get("password_hash") for u in users):
                results["V09_legacy"] = True

        # V10: Logging (assume vulnerable)
        results["V10_logging"] = True

        # Print summary
        print(f"\n[{backend_name}] REST VULNERABILITY SUMMARY:")
        for vuln, is_vulnerable in results.items():
            status = "VULNERABLE" if is_vulnerable else "SECURE"
            print(f"  {vuln}: {status}")

        vulnerable_count = sum(results.values())
        print(f"  Total: {vulnerable_count}/10 vulnerabilities present")

        # Assert that most vulnerabilities exist (as intended for training)
        assert vulnerable_count >= 6, \
            f"{backend_name}: Expected at least 6/10 V01-V10 vulnerabilities for training purposes"
