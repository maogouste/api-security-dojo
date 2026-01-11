"""Isolated vulnerable code implementations."""

from app.vulnerabilities.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    decode_token,
    get_current_user,
    get_current_user_required,
    get_admin_user,
)
from app.vulnerabilities.injection import (
    search_products_vulnerable,
    ping_host_vulnerable,
    dns_lookup_vulnerable,
)

__all__ = [
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "decode_token",
    "get_current_user",
    "get_current_user_required",
    "get_admin_user",
    "search_products_vulnerable",
    "ping_host_vulnerable",
    "dns_lookup_vulnerable",
]
