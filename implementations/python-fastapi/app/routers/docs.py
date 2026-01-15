"""Documentation router for vulnerability explanations.

This module provides endpoints to access detailed documentation
about each vulnerability when the API is in documentation mode.
"""

import json
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.config import settings


router = APIRouter()

# Load vulnerabilities documentation
DOCS_PATH = Path(__file__).parent.parent / "docs" / "vulnerabilities.json"


class ExploitationInfo(BaseModel):
    steps: List[str]
    example_request: str
    example_response: str


class VulnerabilityDoc(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    owasp: str
    cwe: str
    description: str
    vulnerable_endpoint: str
    exploitation: ExploitationInfo
    vulnerable_code: str
    secure_code: str
    remediation: List[str]
    references: List[str]
    flag: Optional[str] = None


class VulnerabilityListItem(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    owasp: str
    cwe: str
    description: str


class CodeComparison(BaseModel):
    id: str
    name: str
    vulnerable_code: str
    secure_code: str
    key_difference: str
    remediation: List[str]
    owasp: str
    cwe: str


def load_vulnerabilities() -> dict:
    """Load vulnerabilities documentation from JSON file."""
    if not DOCS_PATH.exists():
        return {"version": "1.0.0", "vulnerabilities": []}

    with open(DOCS_PATH, "r") as f:
        return json.load(f)


def check_documentation_mode():
    """Check if API is in documentation mode."""
    if settings.mode != "documentation":
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Documentation mode is disabled",
                "message": "Set DOJO_MODE=documentation to access vulnerability details",
                "current_mode": settings.mode,
            }
        )


@router.get("/vulnerabilities", response_model=List[VulnerabilityListItem])
async def list_vulnerabilities(
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
):
    """
    List all documented vulnerabilities.

    In challenge mode: Returns basic information only (id, name, category).
    In documentation mode: Returns full details including exploitation steps.
    """
    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    # Filter by category if specified
    if category:
        vulnerabilities = [v for v in vulnerabilities if v["category"] == category]

    # Filter by severity if specified
    if severity:
        vulnerabilities = [v for v in vulnerabilities if v["severity"] == severity]

    # In challenge mode, return limited info
    if settings.mode == "challenge":
        return [
            VulnerabilityListItem(
                id=v["id"],
                name=v["name"],
                category=v["category"],
                severity=v["severity"],
                owasp=v["owasp"],
                cwe=v["cwe"],
                description=v["description"],
            )
            for v in vulnerabilities
        ]

    # In documentation mode, still return list format
    return [
        VulnerabilityListItem(
            id=v["id"],
            name=v["name"],
            category=v["category"],
            severity=v["severity"],
            owasp=v["owasp"],
            cwe=v["cwe"],
            description=v["description"],
        )
        for v in vulnerabilities
    ]


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityDoc)
async def get_vulnerability(vuln_id: str):
    """
    Get detailed documentation for a specific vulnerability.

    Requires documentation mode to be enabled.
    Returns exploitation steps, vulnerable/secure code examples, and remediation advice.
    """
    check_documentation_mode()

    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        if vuln["id"] == vuln_id:
            return VulnerabilityDoc(**vuln)

    raise HTTPException(
        status_code=404,
        detail=f"Vulnerability {vuln_id} not found"
    )


# Key differences for each vulnerability (educational summaries)
KEY_DIFFERENCES = {
    "V01": "Add authorization check: verify user owns the resource or has admin role",
    "V02": "Use strong secrets from environment + generic error messages",
    "V03": "Use response models (DTOs) to filter sensitive fields",
    "V04": "Implement rate limiting with sliding window or token bucket",
    "V05": "Whitelist allowed fields, never bind request directly to model",
    "V06": "Use parameterized queries, never concatenate user input into SQL",
    "V07": "Validate input strictly, use safe APIs instead of shell execution",
    "V08": "Configure CORS properly, disable debug endpoints in production",
    "V09": "Deprecate and remove old API versions, apply same security controls",
    "V10": "Log security events, implement alerting on suspicious patterns",
    "G01": "Disable introspection in production: introspection=False",
    "G02": "Set query depth limit: max_depth=10",
    "G03": "Limit batch size and implement query cost analysis",
    "G04": "Disable field suggestions in production errors",
    "G05": "Add authorization checks to all resolvers",
}


@router.get("/compare/{vuln_id}", response_model=CodeComparison)
async def compare_code(vuln_id: str):
    """
    Compare vulnerable vs secure code for a specific vulnerability.

    Available in BOTH challenge and documentation modes.
    This is an educational endpoint to help learn secure coding practices.
    """
    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        if vuln["id"] == vuln_id:
            return CodeComparison(
                id=vuln["id"],
                name=vuln["name"],
                vulnerable_code=vuln["vulnerable_code"],
                secure_code=vuln["secure_code"],
                key_difference=KEY_DIFFERENCES.get(vuln_id, "See secure_code for the fix"),
                remediation=vuln["remediation"],
                owasp=vuln["owasp"],
                cwe=vuln["cwe"],
            )

    raise HTTPException(
        status_code=404,
        detail=f"Vulnerability {vuln_id} not found"
    )


@router.get("/compare")
async def list_comparisons():
    """
    List all available code comparisons.
    """
    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    return [
        {
            "id": vuln["id"],
            "name": vuln["name"],
            "key_difference": KEY_DIFFERENCES.get(vuln["id"], ""),
        }
        for vuln in vulnerabilities
    ]


@router.get("/categories")
async def list_categories():
    """List all vulnerability categories."""
    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    categories = {}
    for vuln in vulnerabilities:
        cat = vuln["category"]
        if cat not in categories:
            categories[cat] = {"name": cat, "count": 0, "vulnerabilities": []}
        categories[cat]["count"] += 1
        categories[cat]["vulnerabilities"].append(vuln["id"])

    return list(categories.values())


@router.get("/stats")
async def get_stats():
    """Get statistics about documented vulnerabilities."""
    data = load_vulnerabilities()
    vulnerabilities = data.get("vulnerabilities", [])

    stats = {
        "total": len(vulnerabilities),
        "by_severity": {},
        "by_category": {},
        "rest_api": 0,
        "graphql": 0,
    }

    for vuln in vulnerabilities:
        # Count by severity
        severity = vuln["severity"]
        stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

        # Count by category
        category = vuln["category"]
        stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

        # Count REST vs GraphQL
        if vuln["id"].startswith("V"):
            stats["rest_api"] += 1
        elif vuln["id"].startswith("G"):
            stats["graphql"] += 1

    return stats


@router.get("/mode")
async def get_mode():
    """Get the current API mode."""
    return {
        "mode": settings.mode,
        "documentation_enabled": settings.mode == "documentation",
        "description": (
            "Challenge mode: Limited information, find vulnerabilities yourself"
            if settings.mode == "challenge"
            else "Documentation mode: Full exploitation details and remediation"
        ),
    }
