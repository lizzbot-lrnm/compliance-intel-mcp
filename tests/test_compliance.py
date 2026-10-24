"""
Comprehensive Unit & Live Integration Test Suite for UK & US Compliance,
Sanctions, Corporate/Charity Registry, DNS Security Posture, and US Recall
Screening Engine (`compliance_engine.py`, `mcp_server.py`, and `src/main.py`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

import compliance_engine as ce
import mcp_server
from src.main import execute_actor_action, _write_fallback_dataset


# ---------------------------------------------------------------------------
# 1. Deterministic Unit Tests & Fail-Closed Verification
# ---------------------------------------------------------------------------


def test_score_name_match_deterministic_accuracy() -> None:
    # Exact match
    assert ce._score_name_match("ELECTRA PRO LLC", "ELECTRA PRO LLC") == 1.0
    # Alias match with Cyrillic + Latin
    assert (
        ce._score_name_match(
            "Electra Pro",
            "ELECTRA PRO LLC",
            "OOO ELECTRA PRO;ООО 'ЭЛЕКТРА ПРО'",
        )
        >= 0.90
    )
    # Must NOT match unrelated names due to single-letter Cyrillic stripping
    assert (
        ce._score_name_match(
            "Oxfam",
            "Sergey Fedorovich KHOMYAKOV",
            "Xомяков Сергей Федорович",
        )
        == 0.0
    )
    # Must NOT match solely on corporate stopwords like LLC / Limited
    assert (
        ce._score_name_match(
            "Acme Ventures Limited Liability Company",
            "USM City Limited Liability Company",
        )
        == 0.0
    )


def test_fail_closed_on_upstream_network_error() -> None:
    def failing_text_fetcher(url: str) -> Tuple[str, str]:
        raise ce.ComplianceUpstreamError(
            "Simulated upstream HTTP 503 Service Unavailable",
            source_url=url,
            status_code=503,
        )

    # Clear CSV cache to ensure fetcher is invoked
    ce._CSV_CACHE.clear()
    res = ce.uk_sanctions_and_company_screen(
        entity_name="Test Entity",
        text_fetcher=failing_text_fetcher,
    )
    assert res["status"] == "error"
    assert res["fail_closed"] is True
    assert res["error"]["status_code"] == 503
    assert "source_url" in res["error"]


def test_fail_closed_on_truncated_sanctions_csv() -> None:
    def truncated_fetcher(url: str) -> Tuple[str, str]:
        return ("id,schema,name\n", "2026-10-24T12:00:00Z")

    ce._CSV_CACHE.clear()
    with pytest.raises(ce.ComplianceUpstreamError):
        ce.screen_uk_sanctions("Test", fetcher=truncated_fetcher)


def test_mcp_tools_fail_closed_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_doh(url: str, **kwargs: Any) -> Tuple[Any, str]:
        raise ce.ComplianceUpstreamError("DoH timeout", source_url=url, status_code=504)

    monkeypatch.setattr(ce, "http_get_json", broken_doh)
    res = mcp_server.email_security_posture("example.com")
    assert res["status"] == "error"
    assert res["fail_closed"] is True
    assert res["error"]["status_code"] == 504


def test_mcpize_yaml_x402_configuration() -> None:
    mcpize_path = Path(__file__).resolve().parent.parent / "mcpize.yaml"
    assert mcpize_path.exists()
    content = mcpize_path.read_text(encoding="utf-8")
    assert "protocol: x402" in content
    assert "network: base" in content
    assert 'recipient: "0xfe4404ee088a741DC6F62d4132e21E14B1912940"' in content
    assert 'price: "0.02"' in content
    assert "uk_sanctions_and_company_screen" in content
    assert "email_security_posture" in content


# ---------------------------------------------------------------------------
# 2. Live Public Endpoint Integration Tests (Zero Mocked Responses)
# ---------------------------------------------------------------------------


def test_live_email_security_posture_bbc() -> None:
    res = ce.email_security_posture("bbc.co.uk")
    assert res["status"] == "ok"
    assert res["fail_closed"] is False
    assert res["domain"] == "bbc.co.uk"
    assert res["mx"]["configured"] is True
    assert res["spf"]["configured"] is True
    assert res["dmarc"]["configured"] is True
    assert res["dmarc"]["policy"] in ("reject", "quarantine", "none")
    assert res["security_grade"] in ("A", "B", "C")
    assert len(res["sources"]) >= 4
    for src in res["sources"]:
        assert src["url"].startswith("https://")
        assert src["retrieved_at_utc"].endswith("Z")


def test_live_uk_sanctions_positive_and_negative() -> None:
    # Known designated entity on UK FCDO Russia sanctions list
    pos = ce.screen_uk_sanctions("ELECTRA PRO LLC", max_results=5)
    assert pos["status"] == "ok"
    assert pos["fail_closed"] is False
    assert pos["is_sanctioned_match"] is True
    assert pos["match_count"] >= 1
    assert pos["matches"][0]["match_score"] == 1.0
    assert pos["stats"]["uk_fcdo_rows_scanned"] > 5000
    assert pos["stats"]["uk_ofsi_rows_scanned"] > 10000
    assert len(pos["sources"]) == 2

    # Known non-sanctioned UK charity
    neg = ce.screen_uk_sanctions("Oxfam", max_results=5)
    assert neg["status"] == "ok"
    assert neg["is_sanctioned_match"] is False
    assert neg["match_count"] == 0


def test_live_us_ofac_sanctions_positive_and_negative() -> None:
    pos = ce.screen_us_ofac_sanctions("AEROCARIBBEAN AIRLINES", max_results=5)
    assert pos["status"] == "ok"
    assert pos["is_sanctioned_match"] is True
    assert pos["match_count"] >= 1
    assert pos["stats"]["us_ofac_rows_scanned"] > 10000
    assert pos["sources"][0]["url"] == ce.US_OFAC_OPENSANCTIONS_CSV_URL

    neg = ce.screen_us_ofac_sanctions("Oxfam", max_results=5)
    assert neg["status"] == "ok"
    assert neg["is_sanctioned_match"] is False


def test_live_uk_public_registries_oxfam() -> None:
    reg = ce.lookup_uk_public_registries(
        entity_name="Oxfam",
        company_or_charity_number="202918",
        max_results=3,
    )
    assert reg["status"] == "ok"
    assert reg["fail_closed"] is False
    assert len(reg["gleif_lei_records"]) >= 1
    assert any(r["jurisdiction"] == "GB" for r in reg["gleif_lei_records"])
    assert len(reg["uk_charity_and_org_records"]) >= 1
    assert any(r["charity_number"] == "202918" for r in reg["uk_charity_and_org_records"])
    assert all(s["url"].startswith("https://") for s in reg["sources"])


def test_live_us_regulatory_recalls_fda_cpsc_nhtsa() -> None:
    rec = ce.us_regulatory_recall_and_enforcement_check(
        query="stroller",
        vehicle_make="Ford",
        vehicle_model="F-150",
        vehicle_year=2023,
        max_results=3,
    )
    assert rec["status"] == "ok"
    assert rec["fail_closed"] is False
    assert len(rec["cpsc_consumer_recalls"]) >= 1
    assert len(rec["nhtsa_vehicle_recalls"]) >= 1
    assert rec["total_enforcement_or_recall_hits"] >= 2
    assert len(rec["sources"]) >= 3


def test_live_unified_uk_sanctions_and_company_screen_and_actor_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APIFY_LOCAL_STORAGE_DIR", str(tmp_path))
    items = execute_actor_action(
        {
            "action": "uk_sanctions_and_company_screen",
            "entity_name": "Oxfam",
            "domain": "oxfam.org.uk",
            "company_or_charity_number": "202918",
            "include_us_ofac": True,
            "include_us_recalls": True,
            "max_results": 3,
        }
    )
    assert len(items) == 1
    report = items[0]
    assert report["status"] == "ok"
    assert report["fail_closed"] is False
    assert report["summary"]["overall_risk_level"] == "LOW"
    assert report["summary"]["email_security_grade"] in ("A", "B")
    assert len(report["sources"]) >= 8

    _write_fallback_dataset(items)
    out_file = tmp_path / "datasets" / "default" / "000000001.json"
    assert out_file.exists()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["input"]["entity_name"] == "Oxfam"
