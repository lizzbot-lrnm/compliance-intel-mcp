"""
MCP Server (Model Context Protocol) for UK, EU & US Public-Record Compliance,
Sanctions, Corporate/Charity Registry, EU VIES / UK HMRC VAT, UK Postcode OGL,
RDAP + DNS/DMARC Security Posture, US FDA/CPSC/NHTSA Regulatory Enforcement,
and Pre-Connection MCP Trust Auditing.

Supports both MCP v2 (`MCPServer`) and MCP v1 (`FastMCP`), plus streamable-http /
stdio transports for MCPize (`x402` USDC on Base) and local/remote agent clients.
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerClass
except ImportError:
    from mcp.server.fastmcp import FastMCP as _MCPServerClass  # type: ignore

from compliance_engine import (
    ComplianceUpstreamError,
    audit_mcp_server_trust as _audit_mcp_server_trust,
    lint_apify_mcp_input_schema as _lint_apify_mcp_input_schema,
    extract_uk_scanned_pdf_clauses as _extract_uk_scanned_pdf_clauses,
    search_uk_property_tribunal_rro_precedents as _search_uk_property_tribunal_rro_precedents,
    bulk_email_and_domain_hygiene as _bulk_email_and_domain_hygiene,
    domain_rdap_and_dns_hygiene as _domain_rdap_and_dns_hygiene,
    email_security_posture as _email_security_posture,
    health_and_provenance as _health_and_provenance,
    lookup_uk_postcode_and_council as _lookup_uk_postcode_and_council,
    lookup_uk_public_registries as _lookup_uk_public_registries,
    screen_uk_sanctions as _screen_uk_sanctions,
    screen_us_ofac_sanctions as _screen_us_ofac_sanctions,
    uk_sanctions_and_company_screen as _uk_sanctions_and_company_screen,
    us_regulatory_recall_and_enforcement_check as _us_regulatory_recall_and_enforcement_check,
    verify_eu_uk_vat as _verify_eu_uk_vat,
)

mcp = _MCPServerClass("compliance-intel-mcp")


@mcp.tool()
def health_and_provenance() -> Dict[str, Any]:
    """
    Free ($0.00) health, provenance, and CAIP-2 Base x402 payment route handshake.
    Allows calling agents and MCP registries to verify live government source URLs
    and security hardening before invoking paid screening tools.
    """
    return _health_and_provenance()


@mcp.tool()
def uk_sanctions_and_company_screen(
    entity_name: str,
    domain: Optional[str] = None,
    company_or_charity_number: Optional[str] = None,
    vat_number: Optional[str] = None,
    uk_postcode: Optional[str] = None,
    include_rdap: bool = False,
    include_us_ofac: bool = True,
    include_us_recalls: bool = True,
    vehicle_make: Optional[str] = None,
    vehicle_model: Optional[str] = None,
    vehicle_year: Optional[int] = None,
    max_results: int = 5,
) -> Dict[str, Any]:
    """
    Unified UK, EU & US Compliance & Security Intelligence Screen.
    Checks live UK FCDO Consolidated Sanctions + HM Treasury OFSI Consolidated List,
    UK Charity Commission / Companies House / GLEIF LEI corporate registries,
    EU VIES / UK HMRC VAT validity, UK ONS/OS Postcode & Local Authority Council,
    RDAP + DNS & DMARC email security posture (MX, SPF, DMARC, CAA over DoH),
    US Treasury OFAC SDN list, and US FDA / CPSC / NHTSA enforcement & recalls.
    Every check includes verbatim source URLs and UTC retrieval timestamps, and fails closed.
    """
    return _uk_sanctions_and_company_screen(
        entity_name=entity_name,
        domain=domain,
        company_or_charity_number=company_or_charity_number,
        vat_number=vat_number,
        uk_postcode=uk_postcode,
        include_rdap=include_rdap,
        include_us_ofac=include_us_ofac,
        include_us_recalls=include_us_recalls,
        vehicle_make=vehicle_make,
        vehicle_model=vehicle_model,
        vehicle_year=vehicle_year,
        max_results=max_results,
    )


@mcp.tool()
def verify_eu_uk_vat(vat_number: str) -> Dict[str, Any]:
    """
    Validate an EU Member State, Northern Ireland (XI), or UK (GB) VAT number
    against the live European Commission VIES REST API and HMRC Modulo-97 specification.
    """
    try:
        return _verify_eu_uk_vat(vat_number=vat_number)
    except (ValueError, ComplianceUpstreamError) as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "vat_number": vat_number,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "source_url": getattr(exc, "source_url", None),
                "status_code": getattr(exc, "status_code", None),
            },
        }


@mcp.tool()
def lookup_uk_postcode_and_council(postcode: str) -> Dict[str, Any]:
    """
    Resolve a UK postcode via official ONS/Ordnance Survey Open Government Licence data
    (api.postcodes.io) to Local Authority Council, Civil Parish, Ward, Constituency, and GSS codes.
    """
    try:
        return _lookup_uk_postcode_and_council(postcode=postcode)
    except (ValueError, ComplianceUpstreamError) as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "query_postcode": postcode,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "source_url": getattr(exc, "source_url", None),
                "status_code": getattr(exc, "status_code", None),
            },
        }


@mcp.tool()
def domain_rdap_and_dns_hygiene(domain: str) -> Dict[str, Any]:
    """
    Combined RDAP registration metadata (rdap.org) and Cloudflare/Google DoH email
    security posture audit (MX, SPF, DMARC, CAA) with 0-100 score and A-F grade.
    """
    try:
        return _domain_rdap_and_dns_hygiene(domain=domain)
    except (ValueError, ComplianceUpstreamError) as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "domain": domain,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "source_url": getattr(exc, "source_url", None),
                "status_code": getattr(exc, "status_code", None),
            },
        }


@mcp.tool()
def bulk_email_and_domain_hygiene(domains: List[str], include_rdap: bool = False) -> Dict[str, Any]:
    """
    Batch B2B RevOps domain/MX/SPF/DMARC/CAA hygiene audit for up to 100 domains per call.
    Enforces charged_results_only=True so failed lookups are never billed.
    """
    try:
        return _bulk_email_and_domain_hygiene(domains=domains, include_rdap=include_rdap)
    except (ValueError, ComplianceUpstreamError) as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }


@mcp.tool()
def audit_mcp_server_trust(manifest_or_tools: str, server_name: str = "unknown-mcp-server") -> Dict[str, Any]:
    """
    Deterministic Pre-Connection MCP Trust, Prompt-Injection & Token-Bloat Auditor.
    Scores an MCP tools JSON schema 0-100 for hidden prompt-injection instructions,
    dangerous execution/secret parameters, and token bloat.
    """
    return _audit_mcp_server_trust(manifest_or_tools=manifest_or_tools, server_name=server_name)


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


@mcp.tool()
def lint_apify_mcp_input_schema(
    input_schema_json: str,
    auto_fix_strategy: str = "move_default_to_prefill",
) -> Dict[str, Any]:
    """
    Lint an Apify .actor/input_schema.json for the MCP required+default silent drop bug
    (where Apify MCP Server marks required fields with defaults as optional in tools/list)
    and missing prefill values that break Apify daily maintenance checks. Returns auto-fixed schema.
    """
    return _lint_apify_mcp_input_schema(
        input_schema_or_json=input_schema_json,
        auto_fix_strategy=auto_fix_strategy,
    )


@mcp.tool()
def extract_uk_scanned_pdf_clauses(
    pdf_path: Optional[str] = None,
    pdf_base64: Optional[str] = None,
    pdf_url: Optional[str] = None,
    raw_text: Optional[str] = None,
    document_type: str = "auto",
    semantic_query: Optional[str] = None,
    top_k: int = 5,
) -> Dict[str, Any]:
    """
    Zero-Token UK Scanned PDF & Legal Deed Clause Extractor (pdftotext + pypdfium2 + RapidOCR +
    local FastEmbed BAAI/bge-small-en-v1.5 + ephemeral in-memory sqlite-vec). Extracts Section 106
    (S106) financial contributions & triggers, Companies House MR01 negative pledge / floating charge
    covenants, and Charity Independent Examiner qualifications with strict per-request tenant isolation.
    """
    return _extract_uk_scanned_pdf_clauses(
        pdf_path=pdf_path,
        pdf_base64=pdf_base64,
        pdf_url=pdf_url,
        raw_text=raw_text,
        document_type=document_type,
        semantic_query=semantic_query,
        top_k=top_k,
    )



@mcp.tool()
def search_uk_property_tribunal_rro_precedents(
    query: str = "",
    region: str = "all",
    offence_type: str = "all",
    mitigation: str = "all",
    max_pct: Optional[float] = None,
    max_results: int = 25,
) -> Dict[str, Any]:
    """
    Search UK First-tier Tribunal (Property Chamber) Rent Repayment Order (RRO) precedent decisions
    (Open Government Licence v3.0) by borough/keyword, region, offence type (HMO licensing s.72,
    Selective licensing s.95, unlawful eviction), mitigation factors, and maximum award percentage.
    Returns matched case references, claimed vs awarded GBP, award % of rent, judge summaries, and GOV.UK PDF URLs.
    """
    try:
        return _search_uk_property_tribunal_rro_precedents(
            query=query,
            region=region,
            offence_type=offence_type,
            mitigation=mitigation,
            max_pct=max_pct,
            max_results=max_results,
        )
    except (ValueError, ComplianceUpstreamError) as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "query": query,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "source_url": getattr(exc, "source_url", None),
                "status_code": getattr(exc, "status_code", None),
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
