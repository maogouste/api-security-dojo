"""Shared pytest fixtures for VulnAPI test suite."""

import os
import pytest
import httpx

# Base URL for the API (can be overridden via environment variable)
BASE_URL = os.getenv("VULNAPI_BASE_URL", "http://localhost:8000")


@pytest.fixture
def base_url():
    """Return the base URL for API requests."""
    return BASE_URL


@pytest.fixture
def client():
    """Return an HTTP client for making requests."""
    return httpx.Client(base_url=BASE_URL, timeout=30.0)


@pytest.fixture
def async_client():
    """Return an async HTTP client for making requests."""
    return httpx.AsyncClient(base_url=BASE_URL, timeout=30.0)


@pytest.fixture
def admin_token(client):
    """Get an admin JWT token."""
    response = client.post(
        "/api/login",
        data={"username": "admin", "password": "admin123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def user_token(client):
    """Get a regular user JWT token."""
    response = client.post(
        "/api/login",
        data={"username": "john", "password": "password123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(user_token):
    """Return authorization headers for a regular user."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest.fixture
def admin_headers(admin_token):
    """Return authorization headers for admin."""
    return {"Authorization": f"Bearer {admin_token}"}
