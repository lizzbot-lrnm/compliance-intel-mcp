"""
MCP Server (Model Context Protocol) for UK & US Public-Record Compliance,
Sanctions, Corporate/Charity Registry, DNS/DMARC Security Posture, and
US FDA/CPSC/NHTSA Regulatory Enforcement Screening.

Supports both MCP v2 (`MCPServer`) and MCP v1 (`FastMCP`), plus streamable-http /
stdio transports for MCPize (`x402` USDC on Base) and local/remote agent clients.
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, Optional

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerClass
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServerClass  # type: ignore

from compliance_engine import (
    ComplianceUpstreamError,
    email_security_posture as _email_security_posture,
    lookup_uk_public_registries as _lookup_uk_public_registries,
    screen_uk_sanctions as _screen_uk_sanctions,
    screen_us_ofac_sanctions as _screen_us_ofac_sanctions,
    uk_sanctions_and_company_screen as _uk_sanctions_and_company_screen,
    us_regulatory_recall_and_enforcement_check as _us_regulatory_recall_and_enforcement_check,
)

mcp = _MCPServerClass("compliance-intel-mcp")


@mcp.tool()
def uk_sanctions_and_company_screen(
    entity_name: str,
    domain: Optional[str] = None,
    company_or_charity_number: Optional[str] = None,
    include_us_ofac: bool = True,
    include_us_recalls: bool = True,
    vehicle_make: Optional[str] = None,
    vehicle_model: Optional[str] = None,
    vehicle_year: Optional[int] = None,
    max_results: int = 5,
) -> Dict[str, Any]:
    """
    Unified UK & US Compliance & Security Intelligence Screen.
    Checks live UK FCDO Consolidated Sanctions + HM Treasury OFSI Consolidated List,
    UK Charity Commission / Companies House / GLEIF LEI corporate registries,
    DNS & DMARC email security posture (MX, SPF, DMARC, CAA over DoH),
    US Treasury OFAC SDN list, and US FDA / CPSC / NHTSA enforcement & recalls.
    Every check includes verbatim source URLs and UTC retrieval timestamps, and fails closed.
    """
    return _uk_sanctions_and_company_screen(
        entity_name=entity_name,
        domain=domain,
        company_or_charity_number=company_or_charity_number,
        include_us_ofac=include_us_ofac,
        include_us_recalls=include_us_recalls,
        vehicle_make=vehicle_make,
        vehicle_model=vehicle_model,
        vehicle_year=vehicle_year,
        max_results=max_results,
    )


@mcp.tool()
def email_security_posture(domain: str) -> Dict[str, Any]:
    """
    Deterministic DNS & Email Security Posture audit for a domain over live
    Cloudflare/Google DNS-over-HTTPS (MX, SPF, DMARC policy/pct/rua, CAA) with A-F grading.
    """
    try:
        return _email_security_posture(domain=domain)
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "domain": domain,
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }


@mcp.tool()
def screen_uk_sanctions(query: str, max_results: int = 10, min_score: float = 0.65) -> Dict[str, Any]:
    """
    Screen an organization, person, or vessel against the live UK FCDO Sanctions List
    and UK HM Treasury OFSI Consolidated List of Targets.
    """
    try:
        return _screen_uk_sanctions(query=query, max_results=max_results, min_score=min_score)
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "query": query,
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }


@mcp.tool()
def screen_us_ofac_sanctions(query: str, max_results: int = 10, min_score: float = 0.65) -> Dict[str, Any]:
    """
    Screen an organization, person, or vessel against the live US Treasury OFAC SDN list.
    """
    try:
        return _screen_us_ofac_sanctions(query=query, max_results=max_results, min_score=min_score)
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "query": query,
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }


@mcp.tool()
def lookup_uk_public_registries(
    entity_name: str,
    company_or_charity_number: Optional[str] = None,
    max_results: int = 5,
) -> Dict[str, Any]:
    """
    Cross-check UK Charity Commission / Companies House OrgID records and Global LEI
    Foundation (GLEIF) validated corporate registrations.
    """
    try:
        return _lookup_uk_public_registries(
            entity_name=entity_name,
            company_or_charity_number=company_or_charity_number,
            max_results=max_results,
        )
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "entity_name": entity_name,
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }


@mcp.tool()
def us_regulatory_recall_and_enforcement_check(
    query: str,
    vehicle_make: Optional[str] = None,
    vehicle_model: Optional[str] = None,
    vehicle_year: Optional[int] = None,
    max_results: int = 5,
) -> Dict[str, Any]:
    """
    Check live US FDA (openFDA food/drug enforcement), US CPSC consumer product recalls,
    and US DOT NHTSA vehicle safety recalls.
    """
    try:
        return _us_regulatory_recall_and_enforcement_check(
            query=query,
            vehicle_make=vehicle_make,
            vehicle_model=vehicle_model,
            vehicle_year=vehicle_year,
            max_results=max_results,
        )
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "query": query,
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Compliance Intel MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    args = parser.parse_args()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
