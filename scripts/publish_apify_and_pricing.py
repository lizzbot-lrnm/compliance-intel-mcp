#!/usr/bin/env python3
"""
Helper script to unblock Apify Store search indexing for `technoplusit/compliance-intel-mcp`
(`XK0AWj50YPs0wg1rX`), configure `PAY_PER_EVENT` pricing on `technoplusit/uk-property-tribunal-rro-finder`
(`ZuY8wJtwJO2glaiKG`), and verify/trigger `technoplusit/ecomm-seo-llms-auditor-mcp` once approved.

Defaults to `--dry-run`. Pass `--execute` after user approval to apply changes against Apify API v2.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict

APIFY_BASE = "https://api.apify.com/v2"
COMPLIANCE_ACTOR_ID = "XK0AWj50YPs0wg1rX"
RRO_ACTOR_ID = "ZuY8wJtwJO2glaiKG"


def _load_apify_token() -> str:
    auth_file = Path.home() / ".apify" / "auth.json"
    if auth_file.is_file():
        data = json.loads(auth_file.read_text(encoding="utf-8"))
        tok = str(data.get("token") or "").strip()
        if tok:
            return tok
    raise RuntimeError("Apify auth token not found in ~/.apify/auth.json")


def _api_call(method: str, path: str, token: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
    url = f"{APIFY_BASE}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Apify Store indexing & PPE pricing helper")
    parser.add_argument("--execute", action="store_true", help="Execute live Apify API mutations (requires approval)")
    args = parser.parse_args()

    default_input = {"action": "screen_entity", "query": "iban", "country": "ALL"}
    rro_pricing = [
        {
            "pricingModel": "PAY_PER_EVENT",
            "pricingPerEvent": {
                "actorChargeEvents": {
                    "actor-start": {
                        "eventTitle": "Actor start",
                        "eventDescription": "Container initialization and schema validation",
                        "eventPriceUsd": 0.005,
                    },
                    "rro-search": {
                        "eventTitle": "RRO Precedent & Section 44 Calculation",
                        "eventDescription": "Deterministic UK Property Tribunal RRO precedent search and Section 44 award schedule",
                        "eventPriceUsd": 0.002,
                    },
                }
            },
        }
    ]

    plan = {
        "mode": "EXECUTE" if args.execute else "DRY_RUN",
        "compliance_actor_id": COMPLIANCE_ACTOR_ID,
        "compliance_default_run_input": default_input,
        "rro_actor_id": RRO_ACTOR_ID,
        "rro_pricing_infos": rro_pricing,
    }

    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0

    token = _load_apify_token()
    update_example = _api_call(
        "PUT",
        f"/acts/{COMPLIANCE_ACTOR_ID}",
        token,
        {
            "exampleRunInput": {
                "contentType": "application/json; charset=utf-8",
                "body": json.dumps(default_input),
            }
        },
    )
    run_res = _api_call(
        "POST",
        f"/acts/{COMPLIANCE_ACTOR_ID}/runs?waitForFinish=60",
        token,
        default_input,
    )
    rro_res = _api_call(
        "PUT",
        f"/acts/{RRO_ACTOR_ID}",
        token,
        {"pricingInfos": rro_pricing},
    )
    print(
        json.dumps(
            {
                "status": "ok",
                "compliance_actor_updated": update_example.get("data", {}).get("id"),
                "compliance_run_status": run_res.get("data", {}).get("status"),
                "rro_actor_updated": rro_res.get("data", {}).get("id"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
