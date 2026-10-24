"""
Deterministic UK & US Public-Record Compliance, Sanctions, Registry, DNS Security,
and Regulatory Recall/Enforcement Screening Engine.

Zero LLM cost. Every check runs against live public endpoints, includes verbatim
source URLs and ISO-8601 UTC retrieval timestamps, and fails closed on network
or upstream parse errors.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


USER_AGENT = "ComplianceIntelMCP/1.0 (+https://github.com/lizzbot-lrnm/compliance-intel-mcp)"
DEFAULT_TIMEOUT_SECONDS = 20

# Official live public endpoints
UK_OFSI_CONSOLIDATED_CSV_URL = "https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv"
UK_FCDO_OPENSANCTIONS_CSV_URL = "https://data.opensanctions.org/datasets/latest/gb_fcdo_sanctions/targets.simple.csv"
UK_GOV_SANCTIONS_META_URL = "https://www.gov.uk/api/content/government/publications/the-uk-sanctions-list"

US_OFAC_TREASURY_SDN_CSV_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
US_OFAC_OPENSANCTIONS_CSV_URL = "https://data.opensanctions.org/datasets/latest/us_ofac_sdn/targets.simple.csv"

GLEIF_LEI_API_URL = "https://api.gleif.org/api/v1/lei-records"
FINDTHATCHARITY_RECONCILE_URL = "https://findthatcharity.uk/reconcile"
FINDTHATCHARITY_ORGID_BASE_URL = "https://findthatcharity.uk/orgid"

CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
GOOGLE_DOH_URL = "https://dns.google/resolve"

OPENFDA_ENFORCEMENT_URLS = {
    "food": "https://api.fda.gov/food/enforcement.json",
    "drug": "https://api.fda.gov/drug/enforcement.json",
    "device": "https://api.fda.gov/device/enforcement.json",
}
CPSC_RECALL_URL = "https://www.saferproducts.gov/RestWebServices/Recall"
NHTSA_RECALL_URL = "https://api.nhtsa.gov/recalls/recallsByVehicle"


class ComplianceUpstreamError(RuntimeError):
    """Raised when a live compliance endpoint fails or returns invalid data (fail-closed)."""

    def __init__(self, message: str, source_url: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.source_url = source_url
        self.status_code = status_code


# In-memory TTL cache for bulk CSV feeds so repeated queries within the same run are instant
_CSV_CACHE: Dict[str, Tuple[float, str, str]] = {}
CSV_CACHE_TTL_SECONDS = 900  # 15 minutes


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_get_text(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    allow_404_empty: bool = False,
) -> Tuple[str, str]:
    """
    Fetch text from a live URL with strict fail-closed error handling.
    Returns (response_body, retrieved_at_utc).
    """
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    retrieved_at = utc_now_iso()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if status < 200 or status >= 300:
                raise ComplianceUpstreamError(
                    f"HTTP {status} from {url}",
                    source_url=url,
                    status_code=status,
                )
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return text, retrieved_at
    except urllib.error.HTTPError as exc:
        if allow_404_empty and exc.code == 404:
            return "", retrieved_at
        raise ComplianceUpstreamError(
            f"HTTP error {exc.code} fetching {url}: {exc.reason}",
            source_url=url,
            status_code=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise ComplianceUpstreamError(
            f"Network error fetching {url}: {exc.reason}",
            source_url=url,
        ) from exc
    except TimeoutError as exc:
        raise ComplianceUpstreamError(
            f"Timeout fetching {url}",
            source_url=url,
        ) from exc


def http_get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    allow_404_empty: bool = False,
) -> Tuple[Any, str]:
    """Fetch JSON from a live URL with strict fail-closed error handling."""
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    text, retrieved_at = http_get_text(
        url=url,
        headers=req_headers,
        timeout=timeout,
        allow_404_empty=allow_404_empty,
    )
    if allow_404_empty and text == "":
        return None, retrieved_at
    try:
        return json.loads(text), retrieved_at
    except json.JSONDecodeError as exc:
        raise ComplianceUpstreamError(
            f"Invalid JSON returned from {url}: {exc}",
            source_url=url,
        ) from exc


def _get_cached_csv(
    url: str,
    fetcher: Optional[Callable[[str], Tuple[str, str]]] = None,
) -> Tuple[str, str]:
    """Retrieve a bulk CSV document with in-memory TTL caching."""
    now = time.time()
    cached = _CSV_CACHE.get(url)
    if cached and (now - cached[0]) < CSV_CACHE_TTL_SECONDS:
        return cached[1], cached[2]
    active_fetcher = fetcher or http_get_text
    text, retrieved_at = active_fetcher(url)
    if not text or len(text.strip()) < 50:
        raise ComplianceUpstreamError(
            f"Empty or truncated CSV payload from {url}",
            source_url=url,
        )
    _CSV_CACHE[url] = (now, text, retrieved_at)
    return text, retrieved_at


_CORPORATE_STOPWORDS = {
    "ltd", "limited", "llc", "inc", "incorporated", "corp", "corporation",
    "plc", "co", "company", "group", "holdings", "holding", "international",
    "the", "and", "of", "for", "ooo", "jsc", "pjsc", "fze", "fz", "gmbh", "sa", "liability", "public", "joint", "stock", "private", "llp", "lp", "bv", "nv", "ag",
}


def _normalize_tokens(value: str) -> List[str]:
    # Support Unicode word characters as well as ASCII alphanumeric
    cleaned = re.sub(r"[^\w]+", " ", value.lower(), flags=re.UNICODE).replace("_", " ").strip()
    return [tok for tok in cleaned.split() if len(tok) >= 2]


def _score_name_match(query: str, candidate_name: str, aliases: str = "") -> float:
    """
    Deterministic token-boundary similarity score in [0.0, 1.0].
    Prevents single-letter Cyrillic/Unicode stripping collisions and generic
    corporate suffix false positives.
    """
    q_tokens_all = _normalize_tokens(query)
    if not q_tokens_all:
        return 0.0
    q_norm = " ".join(q_tokens_all)
    q_tokens = set(q_tokens_all)
    q_core = {t for t in q_tokens if t not in _CORPORATE_STOPWORDS} or q_tokens

    candidates = [candidate_name]
    if aliases:
        candidates.extend([a.strip() for a in re.split(r"[;|,]", aliases) if a.strip()])

    best = 0.0
    for cand in candidates:
        c_tokens_all = _normalize_tokens(cand)
        if not c_tokens_all:
            continue
        c_norm = " ".join(c_tokens_all)
        if q_norm == c_norm:
            return 1.0

        c_tokens = set(c_tokens_all)
        c_core = {t for t in c_tokens if t not in _CORPORATE_STOPWORDS} or c_tokens

        common_core = q_core.intersection(c_core)
        if not common_core:
            continue

        core_recall = len(common_core) / len(q_core)
        core_precision = len(common_core) / len(c_core)

        if core_recall == 1.0 and core_precision == 1.0:
            score = 0.96
        elif core_recall == 1.0:
            score = 0.80 + 0.15 * core_precision
        else:
            score = (2 * core_recall * core_precision) / (core_recall + core_precision)

        best = max(best, round(score, 4))
    return round(min(best, 1.0), 4)


def screen_uk_sanctions(
    query: str,
    max_results: int = 10,
    min_score: float = 0.65,
    fetcher: Optional[Callable[[str], Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Screen an entity or individual name against the live UK FCDO Sanctions List
    and UK HM Treasury OFSI Consolidated List.
    Fails closed if upstream data cannot be retrieved or parsed.
    """
    q = (query or "").strip()
    if not q:
        raise ValueError("query must be a non-empty string")

    fcdo_csv, fcdo_ts = _get_cached_csv(UK_FCDO_OPENSANCTIONS_CSV_URL, fetcher=fetcher)
    ofsi_csv, ofsi_ts = _get_cached_csv(UK_OFSI_CONSOLIDATED_CSV_URL, fetcher=fetcher)

    matches: List[Dict[str, Any]] = []
    seen_ids = set()

    # 1. Parse UK FCDO Sanctions CSV
    fcdo_reader = csv.DictReader(io.StringIO(fcdo_csv))
    fcdo_rows_scanned = 0
    for row in fcdo_reader:
        fcdo_rows_scanned += 1
        name = row.get("name", "")
        aliases = row.get("aliases", "")
        identifiers = row.get("identifiers", "")
        score = _score_name_match(q, name, f"{aliases};{identifiers}")
        if score >= min_score:
            rec_id = row.get("id") or name
            seen_ids.add(rec_id)
            matches.append({
                "list": "UK_FCDO_SANCTIONS_LIST",
                "record_id": rec_id,
                "schema": row.get("schema", ""),
                "name": name,
                "aliases": [a for a in aliases.split(";") if a][:10],
                "countries": [c for c in row.get("countries", "").split(";") if c],
                "identifiers": [i for i in identifiers.split(";") if i],
                "program_ids": [p for p in row.get("program_ids", "").split(";") if p],
                "sanctions_summary": (row.get("sanctions") or "")[:400],
                "last_seen": row.get("last_seen", ""),
                "match_score": score,
                "source_url": UK_FCDO_OPENSANCTIONS_CSV_URL,
            })

    # 2. Parse UK OFSI Consolidated List CSV (first line is "Last Updated,DD/MM/YYYY")
    ofsi_lines = ofsi_csv.splitlines()
    ofsi_last_updated = ""
    start_idx = 0
    if ofsi_lines and ofsi_lines[0].startswith("Last Updated"):
        parts = ofsi_lines[0].split(",", 1)
        ofsi_last_updated = parts[1].strip() if len(parts) > 1 else ""
        start_idx = 1

    ofsi_reader = csv.DictReader(io.StringIO("\n".join(ofsi_lines[start_idx:])))
    ofsi_rows_scanned = 0
    for row in ofsi_reader:
        ofsi_rows_scanned += 1
        name_parts = [
            row.get("Name 1", ""),
            row.get("Name 2", ""),
            row.get("Name 3", ""),
            row.get("Name 4", ""),
            row.get("Name 5", ""),
            row.get("Name 6", ""),
        ]
        full_name = " ".join(p.strip() for p in name_parts if p and p.strip())
        if not full_name:
            continue
        group_id = row.get("Group ID", "")
        other_info = row.get("Other Information", "")
        score = _score_name_match(q, full_name)
        if score >= min_score:
            dedup_key = f"OFSI-{group_id}-{full_name.upper()}"
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)
            matches.append({
                "list": "UK_OFSI_CONSOLIDATED_LIST",
                "record_id": f"OFSI-GROUP-{group_id}" if group_id else dedup_key,
                "schema": row.get("Group Type", ""),
                "name": full_name,
                "regime": row.get("Regime", ""),
                "country": row.get("Country", "") or row.get("Nationality", ""),
                "listed_on": row.get("Listed On", ""),
                "uk_sanctions_date_designated": row.get("UK Sanctions List Date Designated", ""),
                "other_information": other_info[:400],
                "match_score": score,
                "source_url": UK_OFSI_CONSOLIDATED_CSV_URL,
            })

    if fcdo_rows_scanned == 0 or ofsi_rows_scanned == 0:
        raise ComplianceUpstreamError(
            "Zero rows parsed from UK sanctions lists; failing closed.",
            source_url=UK_FCDO_OPENSANCTIONS_CSV_URL,
        )

    matches.sort(key=lambda m: m["match_score"], reverse=True)
    top_matches = matches[:max_results]

    return {
        "status": "ok",
        "fail_closed": False,
        "query": q,
        "is_sanctioned_match": len(top_matches) > 0,
        "match_count": len(matches),
        "returned_matches": len(top_matches),
        "matches": top_matches,
        "stats": {
            "uk_fcdo_rows_scanned": fcdo_rows_scanned,
            "uk_ofsi_rows_scanned": ofsi_rows_scanned,
            "uk_ofsi_published_date": ofsi_last_updated,
        },
        "sources": [
            {
                "name": "UK FCDO Sanctions List (OpenSanctions Live Mirror)",
                "url": UK_FCDO_OPENSANCTIONS_CSV_URL,
                "official_publication_url": "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv",
                "retrieved_at_utc": fcdo_ts,
            },
            {
                "name": "UK HM Treasury OFSI Consolidated List of Targets",
                "url": UK_OFSI_CONSOLIDATED_CSV_URL,
                "retrieved_at_utc": ofsi_ts,
            },
        ],
    }


def screen_us_ofac_sanctions(
    query: str,
    max_results: int = 10,
    min_score: float = 0.65,
    fetcher: Optional[Callable[[str], Tuple[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Screen an entity or individual name against the live US Treasury OFAC SDN list.
    """
    q = (query or "").strip()
    if not q:
        raise ValueError("query must be a non-empty string")

    ofac_csv, ofac_ts = _get_cached_csv(US_OFAC_OPENSANCTIONS_CSV_URL, fetcher=fetcher)
    reader = csv.DictReader(io.StringIO(ofac_csv))

    matches: List[Dict[str, Any]] = []
    rows_scanned = 0
    for row in reader:
        rows_scanned += 1
        name = row.get("name", "")
        aliases = row.get("aliases", "")
        identifiers = row.get("identifiers", "")
        score = _score_name_match(q, name, f"{aliases};{identifiers}")
        if score >= min_score:
            matches.append({
                "list": "US_OFAC_SDN",
                "record_id": row.get("id", ""),
                "schema": row.get("schema", ""),
                "name": name,
                "aliases": [a for a in aliases.split(";") if a][:10],
                "countries": [c for c in row.get("countries", "").split(";") if c],
                "identifiers": [i for i in identifiers.split(";") if i],
                "program_ids": [p for p in row.get("program_ids", "").split(";") if p],
                "sanctions_summary": (row.get("sanctions") or "")[:400],
                "last_seen": row.get("last_seen", ""),
                "match_score": score,
                "source_url": US_OFAC_OPENSANCTIONS_CSV_URL,
            })

    if rows_scanned == 0:
        raise ComplianceUpstreamError(
            "Zero rows parsed from US OFAC SDN list; failing closed.",
            source_url=US_OFAC_OPENSANCTIONS_CSV_URL,
        )

    matches.sort(key=lambda m: m["match_score"], reverse=True)
    top_matches = matches[:max_results]

    return {
        "status": "ok",
        "fail_closed": False,
        "query": q,
        "is_sanctioned_match": len(top_matches) > 0,
        "match_count": len(matches),
        "returned_matches": len(top_matches),
        "matches": top_matches,
        "stats": {
            "us_ofac_rows_scanned": rows_scanned,
        },
        "sources": [
            {
                "name": "US Treasury OFAC SDN List (OpenSanctions Live Standardized Feed)",
                "url": US_OFAC_OPENSANCTIONS_CSV_URL,
                "official_publication_url": US_OFAC_TREASURY_SDN_CSV_URL,
                "retrieved_at_utc": ofac_ts,
            }
        ],
    }


def lookup_uk_public_registries(
    entity_name: str,
    company_or_charity_number: Optional[str] = None,
    max_results: int = 5,
    json_fetcher: Optional[Callable[..., Tuple[Any, str]]] = None,
) -> Dict[str, Any]:
    """
    Check UK Charity Commission / Companies House cross-references (via FindThatCharity
    Reconciliation & OrgID JSON APIs) and Global LEI Foundation (GLEIF) UK Companies House
    validated corporate records.
    """
    q = (entity_name or "").strip()
    if not q and not company_or_charity_number:
        raise ValueError("entity_name or company_or_charity_number is required")

    json_fetcher = json_fetcher or http_get_json
    sources: List[Dict[str, str]] = []
    gleif_records: List[Dict[str, Any]] = []
    charity_or_nonprofit_records: List[Dict[str, Any]] = []

    # 1. GLEIF LEI Lookup (includes UK Companies House registeredAs numbers)
    if q:
        gleif_params = urllib.parse.urlencode({
            "filter[entity.legalName]": q,
            "page[size]": str(max_results),
        })
        gleif_url = f"{GLEIF_LEI_API_URL}?{gleif_params}"
        gleif_data, gleif_ts = json_fetcher(
            gleif_url,
            headers={"Accept": "application/vnd.api+json"},
        )
        sources.append({
            "name": "Global LEI Foundation (GLEIF) Corporate & UK Companies House Registry",
            "url": gleif_url,
            "retrieved_at_utc": gleif_ts,
        })
        for item in (gleif_data or {}).get("data", [])[:max_results]:
            attrs = item.get("attributes", {})
            ent = attrs.get("entity", {})
            reg = attrs.get("registration", {})
            legal_addr = ent.get("legalAddress", {})
            gleif_records.append({
                "lei": attrs.get("lei"),
                "legal_name": ent.get("legalName", {}).get("name"),
                "jurisdiction": ent.get("jurisdiction"),
                "registered_as_number": ent.get("registeredAs"),
                "validation_authority_id": reg.get("validatedAt", {}).get("id"),
                "entity_status": ent.get("status"),
                "registration_status": reg.get("status"),
                "legal_address": {
                    "city": legal_addr.get("city"),
                    "region": legal_addr.get("region"),
                    "country": legal_addr.get("country"),
                    "postal_code": legal_addr.get("postalCode"),
                },
                "source_url": f"{GLEIF_LEI_API_URL}/{attrs.get('lei')}",
            })

    # 2. UK Charity & Nonprofit Reconcile Search (FindThatCharity)
    if q:
        reconcile_payload = {"q0": {"query": q, "limit": max_results}}
        reconcile_url = f"{FINDTHATCHARITY_RECONCILE_URL}?{urllib.parse.urlencode({'queries': json.dumps(reconcile_payload)})}"
        rec_data, rec_ts = json_fetcher(reconcile_url)
        sources.append({
            "name": "UK Charity & Nonprofit Reconciliation API (FindThatCharity / Charity Commission)",
            "url": reconcile_url,
            "retrieved_at_utc": rec_ts,
        })
        candidates = ((rec_data or {}).get("q0") or {}).get("result", [])
        for cand in candidates[:max_results]:
            org_id = cand.get("id", "")
            detail_url = f"{FINDTHATCHARITY_ORGID_BASE_URL}/{urllib.parse.quote(org_id)}.json"
            detail_data: Optional[Dict[str, Any]] = None
            try:
                detail_resp, detail_ts = json_fetcher(detail_url, allow_404_empty=True)
                if isinstance(detail_resp, dict):
                    detail_data = detail_resp
                    sources.append({
                        "name": f"UK OrgID Record ({org_id})",
                        "url": detail_url,
                        "retrieved_at_utc": detail_ts,
                    })
            except ComplianceUpstreamError:
                detail_data = None

            charity_or_nonprofit_records.append({
                "org_id": org_id,
                "name": (detail_data or {}).get("name") or cand.get("name"),
                "charity_number": (detail_data or {}).get("charityNumber"),
                "company_number": (detail_data or {}).get("companyNumber"),
                "active": (detail_data or {}).get("active"),
                "date_registered": (detail_data or {}).get("dateRegistered"),
                "date_removed": (detail_data or {}).get("dateRemoved"),
                "latest_income": (detail_data or {}).get("latestIncome"),
                "latest_employees": (detail_data or {}).get("latestEmployees"),
                "url": (detail_data or {}).get("url"),
                "reconciliation_score": cand.get("score"),
                "exact_match": cand.get("match"),
                "source_url": detail_url,
            })

    # 3. Direct OrgID lookup if a specific UK Charity or Companies House number was supplied
    if company_or_charity_number:
        clean_num = company_or_charity_number.strip().upper()
        prefixes = (
            [clean_num]
            if clean_num.startswith("GB-")
            else [f"GB-CHC-{clean_num}", f"GB-COH-{clean_num.zfill(8)}", f"GB-SC-{clean_num}"]
        )
        for org_id in prefixes:
            detail_url = f"{FINDTHATCHARITY_ORGID_BASE_URL}/{urllib.parse.quote(org_id)}.json"
            detail_resp, detail_ts = json_fetcher(detail_url, allow_404_empty=True)
            if isinstance(detail_resp, dict) and detail_resp.get("id"):
                sources.append({
                    "name": f"UK Direct OrgID Record ({org_id})",
                    "url": detail_url,
                    "retrieved_at_utc": detail_ts,
                })
                charity_or_nonprofit_records.append({
                    "org_id": detail_resp.get("id"),
                    "name": detail_resp.get("name"),
                    "charity_number": detail_resp.get("charityNumber"),
                    "company_number": detail_resp.get("companyNumber"),
                    "active": detail_resp.get("active"),
                    "date_registered": detail_resp.get("dateRegistered"),
                    "date_removed": detail_resp.get("dateRemoved"),
                    "latest_income": detail_resp.get("latestIncome"),
                    "latest_employees": detail_resp.get("latestEmployees"),
                    "url": detail_resp.get("url"),
                    "reconciliation_score": 1000.0,
                    "exact_match": True,
                    "source_url": detail_url,
                })
                break

    return {
        "status": "ok",
        "fail_closed": False,
        "entity_name": q,
        "company_or_charity_number": company_or_charity_number,
        "gleif_lei_records": gleif_records,
        "uk_charity_and_org_records": charity_or_nonprofit_records,
        "sources": sources,
    }


def _strip_txt_quotes(txt_data: str) -> str:
    # DNS TXT answers often come as '"v=spf1 ..." "... "'
    parts = re.findall(r'"([^"]*)"', txt_data)
    if parts:
        return "".join(parts)
    return txt_data.strip('"').strip()


def email_security_posture(
    domain: str,
    json_fetcher: Optional[Callable[..., Tuple[Any, str]]] = None,
) -> Dict[str, Any]:
    """
    Evaluate a domain's email & certificate security posture (MX, SPF, DMARC, CAA)
    over live Cloudflare DNS-over-HTTPS (with Google DoH verification/fallback).
    Deterministic security grading (A, B, C, D, F).
    """
    clean_domain = (domain or "").strip().lower()
    clean_domain = re.sub(r"^https?://", "", clean_domain).split("/")[0].strip(".")
    if not clean_domain or "." not in clean_domain or " " in clean_domain:
        raise ValueError(f"Invalid domain name: {domain!r}")

    json_fetcher = json_fetcher or http_get_json
    sources: List[Dict[str, str]] = []

    def query_doh(qname: str, qtype: str) -> List[Dict[str, Any]]:
        cf_url = f"{CLOUDFLARE_DOH_URL}?{urllib.parse.urlencode({'name': qname, 'type': qtype})}"
        try:
            data, ts = json_fetcher(cf_url, headers={"Accept": "application/dns-json"})
            sources.append({
                "name": f"Cloudflare DoH ({qname} {qtype})",
                "url": cf_url,
                "retrieved_at_utc": ts,
            })
        except ComplianceUpstreamError:
            g_url = f"{GOOGLE_DOH_URL}?{urllib.parse.urlencode({'name': qname, 'type': qtype})}"
            data, ts = json_fetcher(g_url, headers={"Accept": "application/json"})
            sources.append({
                "name": f"Google DoH ({qname} {qtype})",
                "url": g_url,
                "retrieved_at_utc": ts,
            })

        if not isinstance(data, dict) or "Status" not in data:
            raise ComplianceUpstreamError(
                f"Malformed DNS-over-HTTPS response for {qname} ({qtype})",
                source_url=cf_url,
            )
        # Status 0 = NOERROR, Status 3 = NXDOMAIN (valid negative answer)
        dns_status = data.get("Status", -1)
        if dns_status not in (0, 3):
            raise ComplianceUpstreamError(
                f"DNS RCODE {dns_status} querying {qname} ({qtype})",
                source_url=cf_url,
            )
        return data.get("Answer", []) or []

    mx_answers = query_doh(clean_domain, "MX")
    txt_answers = query_doh(clean_domain, "TXT")
    dmarc_answers = query_doh(f"_dmarc.{clean_domain}", "TXT")
    caa_answers = query_doh(clean_domain, "CAA")

    # Parse MX
    mx_records: List[Dict[str, Any]] = []
    for ans in mx_answers:
        if ans.get("type") == 15:
            raw_data = str(ans.get("data", "")).strip()
            parts = raw_data.split(None, 1)
            priority = int(parts[0]) if parts and parts[0].isdigit() else 0
            exchange = parts[1].rstrip(".") if len(parts) > 1 else raw_data.rstrip(".")
            if exchange and exchange != ".":
                mx_records.append({"priority": priority, "exchange": exchange, "ttl": ans.get("TTL")})
    mx_records.sort(key=lambda r: r["priority"])

    # Parse SPF
    spf_records: List[str] = []
    for ans in txt_answers:
        if ans.get("type") == 16:
            txt = _strip_txt_quotes(str(ans.get("data", "")))
            if txt.lower().startswith("v=spf1"):
                spf_records.append(txt)

    spf_all_mechanism = None
    spf_strict = False
    if spf_records:
        spf_primary = spf_records[0]
        m = re.search(r"([+\-~?]all)\b", spf_primary, re.I)
        if m:
            spf_all_mechanism = m.group(1).lower()
            spf_strict = spf_all_mechanism in ("-all", "~all")

    # Parse DMARC
    dmarc_records: List[str] = []
    for ans in dmarc_answers:
        if ans.get("type") == 16:
            txt = _strip_txt_quotes(str(ans.get("data", "")))
            if txt.lower().startswith("v=dmarc1"):
                dmarc_records.append(txt)

    dmarc_policy = None
    dmarc_sub_policy = None
    dmarc_pct = 100
    dmarc_rua = None
    if dmarc_records:
        dmarc_primary = dmarc_records[0]
        tags: Dict[str, str] = {}
        for part in dmarc_primary.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        dmarc_policy = tags.get("p", "").lower() or None
        dmarc_sub_policy = tags.get("sp", "").lower() or None
        if "pct" in tags and tags["pct"].isdigit():
            dmarc_pct = int(tags["pct"])
        dmarc_rua = tags.get("rua")

    # Parse CAA
    caa_records: List[str] = []
    for ans in caa_answers:
        if ans.get("type") == 257:
            caa_records.append(str(ans.get("data", "")).strip())

    # Deterministic scoring out of 100
    score = 0
    findings: List[str] = []
    if mx_records:
        score += 15
    else:
        findings.append("No MX records found (domain may not accept mail or uses A-record fallback).")

    if len(spf_records) == 1:
        score += 20
        if spf_all_mechanism == "-all":
            score += 10
        elif spf_all_mechanism == "~all":
            score += 7
        elif spf_all_mechanism in ("+all", "?all"):
            findings.append(f"Permissive SPF qualifier ({spf_all_mechanism}) allows spoofing.")
        else:
            findings.append("SPF record missing explicit '-all' or '~all' enforcement mechanism.")
    elif len(spf_records) > 1:
        score += 10
        findings.append("Multiple SPF TXT records detected (RFC 7208 violation: permerror risk).")
    else:
        findings.append("Missing SPF record (v=spf1).")

    if dmarc_records:
        score += 20
        if dmarc_policy == "reject":
            score += 25
        elif dmarc_policy == "quarantine":
            score += 18
        elif dmarc_policy == "none":
            score += 5
            findings.append("DMARC policy is p=none (monitoring only, does not block spoofing).")
        if dmarc_rua:
            score += 5
        else:
            findings.append("DMARC record has no aggregate reporting URI (rua=).")
    else:
        findings.append("Missing DMARC record at _dmarc subdomain.")

    if caa_records:
        score += 5
    else:
        findings.append("No CAA records restricting Certificate Authorities.")

    score = min(score, 100)
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "status": "ok",
        "fail_closed": False,
        "domain": clean_domain,
        "security_score": score,
        "security_grade": grade,
        "mx": {
            "configured": len(mx_records) > 0,
            "count": len(mx_records),
            "records": mx_records,
        },
        "spf": {
            "configured": len(spf_records) > 0,
            "valid_single_record": len(spf_records) == 1,
            "all_mechanism": spf_all_mechanism,
            "strict_enforcement": spf_strict,
            "records": spf_records,
        },
        "dmarc": {
            "configured": len(dmarc_records) > 0,
            "policy": dmarc_policy,
            "subdomain_policy": dmarc_sub_policy,
            "pct": dmarc_pct if dmarc_records else None,
            "rua": dmarc_rua,
            "enforcing": dmarc_policy in ("reject", "quarantine"),
            "records": dmarc_records,
        },
        "caa": {
            "configured": len(caa_records) > 0,
            "count": len(caa_records),
            "records": caa_records,
        },
        "findings": findings,
        "sources": sources,
    }


def us_regulatory_recall_and_enforcement_check(
    query: str,
    vehicle_make: Optional[str] = None,
    vehicle_model: Optional[str] = None,
    vehicle_year: Optional[int] = None,
    max_results: int = 5,
    json_fetcher: Optional[Callable[..., Tuple[Any, str]]] = None,
) -> Dict[str, Any]:
    """
    Screen a company, brand, or product keyword across live US federal safety and
    enforcement APIs:
      1. US FDA openFDA Enforcement Reports (Food & Drug recalls)
      2. US CPSC (SaferProducts.gov) Consumer Product Recalls
      3. US NHTSA Vehicle Safety Recalls (when vehicle_make/model/year provided)
    Fails closed if live APIs fail with network/server errors.
    """
    q = (query or "").strip()
    if not q and not (vehicle_make and vehicle_model and vehicle_year):
        raise ValueError("query or (vehicle_make, vehicle_model, vehicle_year) is required")

    json_fetcher = json_fetcher or http_get_json
    sources: List[Dict[str, str]] = []
    fda_recalls: List[Dict[str, Any]] = []
    cpsc_recalls: List[Dict[str, Any]] = []
    nhtsa_recalls: List[Dict[str, Any]] = []

    if q:
        # 1. openFDA Food & Drug Enforcement
        safe_q = re.sub(r'["\\]', "", q)
        for category in ("food", "drug"):
            base_url = OPENFDA_ENFORCEMENT_URLS[category]
            search_expr = f'recalling_firm:"{safe_q}"+product_description:"{safe_q}"+reason_for_recall:"{safe_q}"'
            fda_url = f"{base_url}?search={urllib.parse.quote(search_expr, safe=':+\\\"')}&limit={max_results}"
            # openFDA returns HTTP 404 when 0 matches are found
            fda_data, fda_ts = json_fetcher(fda_url, allow_404_empty=True)
            sources.append({
                "name": f"US FDA openFDA {category.capitalize()} Enforcement API",
                "url": fda_url,
                "retrieved_at_utc": fda_ts,
            })
            if isinstance(fda_data, dict):
                for item in fda_data.get("results", [])[:max_results]:
                    fda_recalls.append({
                        "agency": "US_FDA",
                        "category": category,
                        "recall_number": item.get("recall_number"),
                        "recalling_firm": item.get("recalling_firm"),
                        "classification": item.get("classification"),
                        "status": item.get("status"),
                        "product_description": (item.get("product_description") or "")[:300],
                        "reason_for_recall": (item.get("reason_for_recall") or "")[:300],
                        "report_date": item.get("report_date"),
                        "state": item.get("state"),
                        "country": item.get("country"),
                        "source_url": fda_url,
                    })

        # 2. US CPSC SaferProducts Recall API
        cpsc_params = urllib.parse.urlencode({"format": "json", "RecallTitle": q})
        cpsc_url = f"{CPSC_RECALL_URL}?{cpsc_params}"
        cpsc_data, cpsc_ts = json_fetcher(cpsc_url)
        sources.append({
            "name": "US CPSC SaferProducts.gov Consumer Recall API",
            "url": cpsc_url,
            "retrieved_at_utc": cpsc_ts,
        })
        if isinstance(cpsc_data, list):
            for item in cpsc_data[:max_results]:
                cpsc_recalls.append({
                    "agency": "US_CPSC",
                    "recall_id": item.get("RecallID"),
                    "recall_number": item.get("RecallNumber"),
                    "recall_date": item.get("RecallDate"),
                    "title": item.get("Title"),
                    "description": (item.get("Description") or "")[:300],
                    "url": item.get("URL"),
                    "source_url": cpsc_url,
                })

    # 3. US NHTSA Vehicle Safety Recalls
    if vehicle_make and vehicle_model and vehicle_year:
        nhtsa_params = urllib.parse.urlencode({
            "make": vehicle_make.strip(),
            "model": vehicle_model.strip(),
            "modelYear": str(vehicle_year),
        })
        nhtsa_url = f"{NHTSA_RECALL_URL}?{nhtsa_params}"
        nhtsa_data, nhtsa_ts = json_fetcher(nhtsa_url, allow_404_empty=True)
        sources.append({
            "name": "US DOT NHTSA Vehicle Safety Recalls API",
            "url": nhtsa_url,
            "retrieved_at_utc": nhtsa_ts,
        })
        if isinstance(nhtsa_data, dict):
            for item in nhtsa_data.get("results", [])[:max_results]:
                nhtsa_recalls.append({
                    "agency": "US_NHTSA",
                    "campaign_number": item.get("NHTSACampaignNumber"),
                    "manufacturer": item.get("Manufacturer"),
                    "component": item.get("Component"),
                    "summary": (item.get("Summary") or "")[:300],
                    "consequence": (item.get("Consequence") or "")[:300],
                    "remedy": (item.get("Remedy") or "")[:300],
                    "report_received_date": item.get("ReportReceivedDate"),
                    "source_url": nhtsa_url,
                })

    total_hits = len(fda_recalls) + len(cpsc_recalls) + len(nhtsa_recalls)
    return {
        "status": "ok",
        "fail_closed": False,
        "query": q,
        "total_enforcement_or_recall_hits": total_hits,
        "fda_enforcement_recalls": fda_recalls,
        "cpsc_consumer_recalls": cpsc_recalls,
        "nhtsa_vehicle_recalls": nhtsa_recalls,
        "sources": sources,
    }


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
    text_fetcher: Optional[Callable[[str], Tuple[str, str]]] = None,
    json_fetcher: Optional[Callable[..., Tuple[Any, str]]] = None,
) -> Dict[str, Any]:
    """
    Unified, deterministic UK & US Compliance & Security Intelligence Screen:
      1. UK FCDO Sanctions List + UK HM Treasury OFSI Consolidated List
      2. UK Charity Commission / Companies House / GLEIF LEI Registry cross-check
      3. Domain Email & DNS Security Posture (MX, SPF, DMARC, CAA over DoH) if domain supplied
      4. US Treasury OFAC SDN Sanctions List
      5. US FDA / CPSC / NHTSA Recall & Enforcement Screening

    Fails closed (`status: "error"`, `fail_closed: True`) if any live upstream source
    fails or returns unparseable data.
    """
    started_at = utc_now_iso()
    name = (entity_name or "").strip()
    if not name:
        raise ValueError("entity_name must be a non-empty string")

    try:
        uk_sanctions = screen_uk_sanctions(
            query=name,
            max_results=max_results,
            fetcher=text_fetcher,
        )
        uk_registries = lookup_uk_public_registries(
            entity_name=name,
            company_or_charity_number=company_or_charity_number,
            max_results=max_results,
            json_fetcher=json_fetcher,
        )

        dns_posture: Optional[Dict[str, Any]] = None
        if domain and domain.strip():
            dns_posture = email_security_posture(
                domain=domain.strip(),
                json_fetcher=json_fetcher,
            )

        us_ofac: Optional[Dict[str, Any]] = None
        if include_us_ofac:
            us_ofac = screen_us_ofac_sanctions(
                query=name,
                max_results=max_results,
                fetcher=text_fetcher,
            )

        us_recalls: Optional[Dict[str, Any]] = None
        if include_us_recalls:
            us_recalls = us_regulatory_recall_and_enforcement_check(
                query=name,
                vehicle_make=vehicle_make,
                vehicle_model=vehicle_model,
                vehicle_year=vehicle_year,
                max_results=max_results,
                json_fetcher=json_fetcher,
            )

        # Aggregate risk flags deterministically
        risk_flags: List[str] = []
        if uk_sanctions["is_sanctioned_match"]:
            risk_flags.append(f"UK_SANCTIONS_MATCH ({uk_sanctions['match_count']} hits)")
        if us_ofac and us_ofac["is_sanctioned_match"]:
            risk_flags.append(f"US_OFAC_SDN_MATCH ({us_ofac['match_count']} hits)")
        if dns_posture and dns_posture["security_grade"] in ("D", "F"):
            risk_flags.append(f"WEAK_EMAIL_SECURITY_POSTURE (Grade {dns_posture['security_grade']})")
        if us_recalls and us_recalls["total_enforcement_or_recall_hits"] > 0:
            risk_flags.append(
                f"US_REGULATORY_RECALL_OR_ENFORCEMENT ({us_recalls['total_enforcement_or_recall_hits']} hits)"
            )

        # Collect all verbatim sources
        all_sources: List[Dict[str, str]] = []
        for section in (uk_sanctions, uk_registries, dns_posture, us_ofac, us_recalls):
            if section and "sources" in section:
                all_sources.extend(section["sources"])

        overall_risk_level = "LOW"
        if uk_sanctions["is_sanctioned_match"] or (us_ofac and us_ofac["is_sanctioned_match"]):
            overall_risk_level = "CRITICAL"
        elif len(risk_flags) > 0:
            overall_risk_level = "MEDIUM"

        return {
            "status": "ok",
            "fail_closed": False,
            "screened_at_utc": started_at,
            "completed_at_utc": utc_now_iso(),
            "input": {
                "entity_name": name,
                "domain": domain,
                "company_or_charity_number": company_or_charity_number,
                "include_us_ofac": include_us_ofac,
                "include_us_recalls": include_us_recalls,
            },
            "summary": {
                "overall_risk_level": overall_risk_level,
                "risk_flags": risk_flags,
                "uk_sanctions_hits": uk_sanctions["match_count"],
                "us_ofac_hits": us_ofac["match_count"] if us_ofac else 0,
                "gleif_lei_records_found": len(uk_registries["gleif_lei_records"]),
                "uk_charity_or_org_records_found": len(uk_registries["uk_charity_and_org_records"]),
                "email_security_grade": dns_posture["security_grade"] if dns_posture else None,
                "us_recall_or_enforcement_hits": (
                    us_recalls["total_enforcement_or_recall_hits"] if us_recalls else 0
                ),
            },
            "uk_sanctions": uk_sanctions,
            "uk_registries": uk_registries,
            "email_security_posture": dns_posture,
            "us_ofac_sanctions": us_ofac,
            "us_regulatory_recalls": us_recalls,
            "sources": all_sources,
        }
    except ComplianceUpstreamError as exc:
        return {
            "status": "error",
            "fail_closed": True,
            "screened_at_utc": started_at,
            "completed_at_utc": utc_now_iso(),
            "error": {
                "type": "ComplianceUpstreamError",
                "message": str(exc),
                "source_url": exc.source_url,
                "status_code": exc.status_code,
            },
        }
