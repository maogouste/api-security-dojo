"""
Pytest configuration for cross-implementation API Security Dojo tests.

Tests REST (V01-V10) and GraphQL (G01-G05) vulnerabilities across all backends:
- Python FastAPI: http://localhost:3001
- Go Gin:         http://localhost:3002
- PHP:            http://localhost:3003
- Java Spring:    http://localhost:3004
- Node Express:   http://localhost:3005

Usage:
    # Test all implementations
    pytest tests/cross-implementation/ -v

    # Test specific backend
    pytest tests/cross-implementation/ -v -k "python"
    pytest tests/cross-implementation/ -v -k "go"

    # Test specific vulnerability type
    pytest tests/cross-implementation/ -v -k "V01"      # REST BOLA
    pytest tests/cross-implementation/ -v -k "V06"      # REST SQLi
    pytest tests/cross-implementation/ -v -k "G01"      # GraphQL Introspection

    # Test REST or GraphQL only
    pytest tests/cross-implementation/test_rest_vulnerabilities.py -v
    pytest tests/cross-implementation/test_graphql_vulnerabilities.py -v
"""

import os
import pytest
import httpx

pytest_plugins = ('pytest_asyncio',)

# Backend configurations
BACKENDS = {
    "python": {"url": "http://localhost:8000", "graphql_path": "/graphql/"},
    "go": {"url": "http://localhost:3002", "graphql_path": "/graphql"},
    "php": {"url": "http://localhost:3003", "graphql_path": "/graphql"},
    "java": {"url": "http://localhost:3004", "graphql_path": "/graphql"},
    "node": {"url": "http://localhost:3005", "graphql_path": "/graphql"},
    "rust": {"url": "http://localhost:3006", "graphql_path": "/graphql"},
}

# Allow override via environment variable
SELECTED_BACKENDS = os.environ.get("DOJO_BACKENDS", "python,go,php,java,node,rust").split(",")


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "asyncio: mark test as async")
    for backend in BACKENDS:
        config.addinivalue_line("markers", f"{backend}: mark test for {backend} backend")


def pytest_generate_tests(metafunc):
    """Parameterize tests with backend configurations."""
    if "backend" in metafunc.fixturenames:
        backends_to_test = [
            (name, config)
            for name, config in BACKENDS.items()
            if name in SELECTED_BACKENDS
        ]
        metafunc.parametrize(
            "backend",
            backends_to_test,
            ids=[b[0] for b in backends_to_test]
        )


@pytest.fixture
def backend_url(backend):
    """Return the base URL for the backend."""
    return backend[1]["url"]


@pytest.fixture
def graphql_url(backend):
    """Return the full GraphQL endpoint URL."""
    name, config = backend
    return f"{config['url']}{config['graphql_path']}"


@pytest.fixture
def backend_name(backend):
    """Return the backend name."""
    return backend[0]


@pytest.fixture
async def http_client():
    """Create an async HTTP client."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        yield client


@pytest.fixture
def is_backend_running(backend):
    """Check if the backend is running via /health endpoint."""
    name, config = backend
    try:
        response = httpx.get(f"{config['url']}/health", timeout=2.0)
        return response.status_code == 200
    except (httpx.ConnectError, httpx.TimeoutException):
        return False


def pytest_collection_modifyitems(config, items):
    """Skip tests for backends that are not running."""
    for item in items:
        # Get backend from test parameters
        if hasattr(item, 'callspec') and 'backend' in item.callspec.params:
            backend_name, backend_config = item.callspec.params['backend']
            try:
                response = httpx.get(f"{backend_config['url']}/health", timeout=2.0)
                if response.status_code != 200:
                    item.add_marker(pytest.mark.skip(
                        reason=f"{backend_name} backend not healthy at {backend_config['url']}"
                    ))
            except (httpx.ConnectError, httpx.TimeoutException):
                item.add_marker(pytest.mark.skip(
                    reason=f"{backend_name} backend not running at {backend_config['url']}"
                ))
