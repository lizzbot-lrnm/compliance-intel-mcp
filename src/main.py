"""
Apify Actor entrypoint for UK, EU & US Public-Record Compliance, Sanctions,
Corporate/Charity Registry, EU VIES / UK HMRC VAT, UK Postcode OGL, RDAP + DNS/DMARC
Security Posture, US FDA/CPSC/NHTSA Enforcement, and MCP Trust Auditing.

Supports:
  1. Native Apify Python SDK (`apify.Actor`) execution on Apify Cloud / CLI
  2. Direct filesystem fallback writing to `/apify_storage/datasets/default` or
     `storage/datasets/default` when executed outside the SDK harness.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure root module path is importable
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from compliance_engine import (
    audit_mcp_server_trust,
    lint_apify_mcp_input_schema,
    extract_uk_scanned_pdf_clauses,
    search_uk_property_tribunal_rro_precedents,
    bulk_email_and_domain_hygiene,
    domain_rdap_and_dns_hygiene,
    email_security_posture,
    health_and_provenance,
    lookup_uk_postcode_and_council,
    lookup_uk_public_registries,
    screen_uk_sanctions,
    screen_us_ofac_sanctions,
    uk_sanctions_and_company_screen,
    us_regulatory_recall_and_enforcement_check,
    verify_eu_uk_vat,
)


def execute_actor_action(actor_input: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministically process an Apify Actor input payload and return dataset items.
    Supports single-entity or batch (`entities` list, bounded <= 25) screening.
    """
    action = str(actor_input.get("action") or "uk_sanctions_and_company_screen").strip()
    max_results = min(max(1, int(actor_input.get("max_results") or 5)), 50)

    # Support batch list of entities if provided (bounded to 25 per Worf DoS hardening)
    entities = actor_input.get("entities")
    if isinstance(entities, list) and len(entities) > 0:
        results: List[Dict[str, Any]] = []
        for item in entities[:25]:
            if isinstance(item, str):
                sub_input = dict(actor_input)
                sub_input.pop("entities", None)
                sub_input["entity_name"] = item
                results.extend(execute_actor_action(sub_input))
            elif isinstance(item, dict):
                sub_input = dict(actor_input)
                sub_input.pop("entities", None)
                sub_input.update(item)
                results.extend(execute_actor_action(sub_input))
        return results

    entity_name = str(actor_input.get("entity_name") or actor_input.get("query") or "Oxfam").strip()
    domain = actor_input.get("domain")
    domains = actor_input.get("domains")
    company_or_charity_number = actor_input.get("company_or_charity_number")
    vat_number = actor_input.get("vat_number")
    uk_postcode = actor_input.get("uk_postcode")
    include_rdap = bool(actor_input.get("include_rdap", False))
    include_us_ofac = bool(actor_input.get("include_us_ofac", True))
    include_us_recalls = bool(actor_input.get("include_us_recalls", True))
    vehicle_make = actor_input.get("vehicle_make")
    vehicle_model = actor_input.get("vehicle_model")
    vehicle_year = actor_input.get("vehicle_year")
    if vehicle_year is not None and str(vehicle_year).strip() != "":
        vehicle_year = int(vehicle_year)
    else:
        vehicle_year = None

    if action == "health_and_provenance":
        return [health_and_provenance()]
    if action == "verify_eu_uk_vat":
        target_vat = str(vat_number or entity_name).strip()
        return [verify_eu_uk_vat(vat_number=target_vat)]
    if action == "lookup_uk_postcode_and_council":
        target_pc = str(uk_postcode or entity_name).strip()
        return [lookup_uk_postcode_and_council(postcode=target_pc)]
    if action == "domain_rdap_and_dns_hygiene":
        target_domain = str(domain or entity_name).strip()
        return [domain_rdap_and_dns_hygiene(domain=target_domain)]
    if action == "bulk_email_and_domain_hygiene":
        domain_list = domains if isinstance(domains, list) and domains else [str(domain or entity_name).strip()]
        return [bulk_email_and_domain_hygiene(domains=domain_list, include_rdap=include_rdap)]
    if action == "search_uk_property_tribunal_rro_precedents":
        q_rro = str(actor_input.get("query") or actor_input.get("entity_name") or "").strip()
        if q_rro == "Oxfam" and "query" not in actor_input and "entity_name" not in actor_input:
            q_rro = ""
        max_pct_raw = actor_input.get("max_pct")
        max_pct_val = float(max_pct_raw) if max_pct_raw is not None and str(max_pct_raw).strip() != "" else None
        return [
            search_uk_property_tribunal_rro_precedents(
                query=q_rro,
                region=str(actor_input.get("region") or "all"),
                offence_type=str(actor_input.get("offence_type") or "all"),
                mitigation=str(actor_input.get("mitigation") or "all"),
                max_pct=max_pct_val,
                max_results=max_results,
            )
        ]
    if action == "extract_uk_scanned_pdf_clauses":
        return [
            extract_uk_scanned_pdf_clauses(
                pdf_url=actor_input.get("pdf_url"),
                pdf_base64=actor_input.get("pdf_base64"),
                raw_text=actor_input.get("raw_text") or actor_input.get("query"),
                document_type=str(actor_input.get("document_type") or "auto"),
                semantic_query=actor_input.get("semantic_query"),
            )
        ]
    if action == "lint_apify_mcp_input_schema":
        schema_payload = actor_input.get("input_schema_json") or actor_input.get("manifest_or_tools") or actor_input.get("query") or "{}"
        strategy = str(actor_input.get("auto_fix_strategy") or "move_default_to_prefill")
        return [lint_apify_mcp_input_schema(input_schema_or_json=schema_payload, auto_fix_strategy=strategy)]
    if action == "audit_mcp_server_trust":
        manifest = actor_input.get("manifest_or_tools") or actor_input.get("query") or "{}"
        server_name = str(actor_input.get("server_name") or entity_name or "unknown-mcp-server")
        return [audit_mcp_server_trust(manifest_or_tools=manifest, server_name=server_name)]
    if action == "email_security_posture":
        target_domain = str(domain or entity_name).strip()
        return [email_security_posture(domain=target_domain)]
    if action == "screen_uk_sanctions":
        return [screen_uk_sanctions(query=entity_name, max_results=max_results)]
    if action == "screen_us_ofac_sanctions":
        return [screen_us_ofac_sanctions(query=entity_name, max_results=max_results)]
    if action == "lookup_uk_public_registries":
        return [
            lookup_uk_public_registries(
                entity_name=entity_name,
                company_or_charity_number=company_or_charity_number,
                max_results=max_results,
            )
        ]
    if action == "us_regulatory_recall_and_enforcement_check":
        return [
            us_regulatory_recall_and_enforcement_check(
                query=entity_name,
                vehicle_make=vehicle_make,
                vehicle_model=vehicle_model,
                vehicle_year=vehicle_year,
                max_results=max_results,
            )
        ]

    # Default comprehensive screen: uk_sanctions_and_company_screen
    report = uk_sanctions_and_company_screen(
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
    return [report]


def _write_fallback_dataset(items: List[Dict[str, Any]]) -> None:
    """Write dataset items to local /apify_storage/datasets/default if writable."""
    storage_roots = [
        Path(os.environ.get("APIFY_LOCAL_STORAGE_DIR", "")),
        Path("/apify_storage"),
        ROOT_DIR / "storage",
    ]
    for root in storage_roots:
        if not str(root):
            continue
        try:
            ds_dir = root / "datasets" / "default"
            ds_dir.mkdir(parents=True, exist_ok=True)
            for idx, item in enumerate(items, start=1):
                out_file = ds_dir / f"{idx:09d}.json"
                out_file.write_text(json.dumps(item, indent=2), encoding="utf-8")
            break
        except OSError:
            continue


async def main() -> None:
    try:
        from apify import Actor

        async with Actor:
            actor_input = await Actor.get_input() or {}
            Actor.log.info(f"Running UK/EU/US Compliance Intel Actor with input: {actor_input}")
            items = execute_actor_action(actor_input)
            strict_fail = bool(actor_input.get("strict_fail_closed", False))
            for item in items:
                if item.get("status") == "error" and item.get("fail_closed"):
                    Actor.log.warning(f"Upstream check reported fail_closed error: {item.get('error')}")
                    if strict_fail:
                        await Actor.push_data(item)
                        await Actor.fail(status_message=str(item.get("error", {}).get("message", "Failed closed")))
                        return
                    fallback = health_and_provenance()
                    fallback["upstream_diagnostic"] = item.get("error")
                    fallback["input"] = actor_input
                    item = fallback
                await Actor.push_data(item)
            await Actor.set_value("OUTPUT", items[0] if len(items) == 1 else items)
            Actor.log.info(f"Successfully pushed {len(items)} compliance report(s) to default dataset.")
    except ImportError:
        raw_input = os.environ.get("ACTOR_INPUT", "{}")
        actor_input = json.loads(raw_input) if raw_input else {}
        items = execute_actor_action(actor_input)
        _write_fallback_dataset(items)
        print(json.dumps(items, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
