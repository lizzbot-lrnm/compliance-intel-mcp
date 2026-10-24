"""
Apify Actor entrypoint for UK & US Public-Record Compliance, Sanctions,
Corporate/Charity Registry, DNS/DMARC Security Posture, and US FDA/CPSC/NHTSA
Enforcement & Recall Screening.

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
    email_security_posture,
    lookup_uk_public_registries,
    screen_uk_sanctions,
    screen_us_ofac_sanctions,
    uk_sanctions_and_company_screen,
    us_regulatory_recall_and_enforcement_check,
)


def execute_actor_action(actor_input: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministically process an Apify Actor input payload and return dataset items.
    Supports single-entity or batch (`entities` list) screening.
    """
    action = str(actor_input.get("action") or "uk_sanctions_and_company_screen").strip()
    max_results = int(actor_input.get("max_results") or 5)

    # Support batch list of entities if provided
    entities = actor_input.get("entities")
    if isinstance(entities, list) and len(entities) > 0:
        results: List[Dict[str, Any]] = []
        for item in entities:
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
    company_or_charity_number = actor_input.get("company_or_charity_number")
    include_us_ofac = bool(actor_input.get("include_us_ofac", True))
    include_us_recalls = bool(actor_input.get("include_us_recalls", True))
    vehicle_make = actor_input.get("vehicle_make")
    vehicle_model = actor_input.get("vehicle_model")
    vehicle_year = actor_input.get("vehicle_year")
    if vehicle_year is not None and str(vehicle_year).strip() != "":
        vehicle_year = int(vehicle_year)
    else:
        vehicle_year = None

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
            Actor.log.info(f"Running UK/US Compliance Intel Actor with input: {actor_input}")
            items = execute_actor_action(actor_input)
            for item in items:
                if item.get("status") == "error" and item.get("fail_closed"):
                    Actor.log.error(f"Upstream check failed closed: {item.get('error')}")
                    await Actor.push_data(item)
                    await Actor.fail(status_message=str(item.get("error", {}).get("message", "Failed closed")))
                    return
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
