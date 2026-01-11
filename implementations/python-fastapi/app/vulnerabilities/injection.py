"""Vulnerable injection implementations."""

import subprocess
import sqlite3
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.models import Product


async def search_products_vulnerable(
    db: AsyncSession,
    search_term: str
) -> List[dict]:
    """
    Search products with SQL injection vulnerability.

    VULNERABILITY V06: Direct string concatenation in SQL query
    Example exploit: ' OR '1'='1' --
    Example exploit: ' UNION SELECT id, username, email, password_hash, ssn, credit_card, secret_note, role FROM users --
    """
    # VULNERABLE: String concatenation in SQL
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"

    result = await db.execute(text(query))
    rows = result.fetchall()

    # Convert to dict
    products = []
    for row in rows:
        products.append({
            "id": row[0],
            "name": row[1],
            "description": row[2],
            "price": row[3],
            "stock": row[4],
            "category": row[5],
        })

    return products


def ping_host_vulnerable(host: str) -> dict:
    """
    Ping a host with command injection vulnerability.

    VULNERABILITY V07: Direct command execution with user input
    Example exploit: 127.0.0.1; cat /etc/passwd
    Example exploit: 127.0.0.1 && whoami
    Example exploit: $(cat /etc/passwd)
    """
    # VULNERABLE: Direct command execution with user input
    command = f"ping -c 1 {host}"

    try:
        result = subprocess.run(
            command,
            shell=True,  # VULNERABLE: shell=True with user input
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "success": result.returncode == 0,
            "command": command,  # VULNERABILITY: Exposing executed command
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Command timed out"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def dns_lookup_vulnerable(domain: str) -> dict:
    """
    DNS lookup with command injection vulnerability.

    VULNERABILITY V07: Another command injection vector
    """
    command = f"nslookup {domain}"

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "success": result.returncode == 0,
            "domain": domain,
            "output": result.stdout,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
