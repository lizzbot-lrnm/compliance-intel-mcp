# UK & US Statutory Compliance & Property Tribunal MCP Server (`compliance-intel-mcp`)

Deterministic, **zero-LLM-cost** UK, EU & US statutory compliance, sanctions, corporate registry, DNS/DMARC security, scanned legal PDF clause extraction, and UK Property Tribunal Rent Repayment Order (RRO) precedent engine (`15 tools`).

Runs both as:
1. **An Apify Actor** ([`technoplusit/compliance-intel-mcp`](https://apify.com/technoplusit/compliance-intel-mcp)) writing structured compliance & legal precedent reports to the default Apify dataset.
2. **An MCP Server (`mcp_server.py`) + `mcpize.yaml`** with native `x402` USDC on Base pay-per-call settlement (`0.01–0.03` USDC/call to `0xfe4404ee088a741DC6F62d4132e21E14B1912940`).

Every check queries **live government and public authority endpoints** (zero mocked data), embeds **verbatim source URLs** and **ISO-8601 UTC retrieval timestamps**, and **fails closed** on upstream network or parsing errors.

---

## Live Public Data Sources Queried

| Domain | Official / Public Authority Source | Endpoint |
| :--- | :--- | :--- |
| **UK Property Tribunal RRO Precedents** | UK First-tier Tribunal (Property Chamber) Rent Repayment Order Decisions (OGL v3.0) | `https://parish.technoplusit.co.uk/api/rro-search` & `https://www.gov.uk/residential-property-tribunal-decisions` |
| **UK Sanctions (FCDO)** | UK Foreign, Commonwealth & Development Office Sanctions List (OpenSanctions Live Standardized Feed) | `https://data.opensanctions.org/datasets/latest/gb_fcdo_sanctions/targets.simple.csv` |
| **UK Financial Sanctions (OFSI)** | UK HM Treasury Office of Financial Sanctions Implementation Consolidated List | `https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv` |
| **UK Charity & Company Registry** | UK Charity Commission / Companies House Cross-Reference (FindThatCharity Reconciliation & OrgID JSON API) | `https://findthatcharity.uk/reconcile` & `https://findthatcharity.uk/orgid/{id}.json` |
| **Global & UK Corporate LEI** | Global Legal Entity Identifier Foundation (GLEIF) API v1 (with UK Companies House `RA000585` / Charity `RA000589` validation) | `https://api.gleif.org/api/v1/lei-records` |
| **EU VIES & UK HMRC VAT** | European Commission VIES REST API & UK HMRC Modulo-97 Specification | `https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{country}/vat/{number}` |
| **UK ONS/OS Postcode & Council** | ONS / Ordnance Survey Open Government Licence Postcodes API | `https://api.postcodes.io/postcodes/{postcode}` |
| **Email, RDAP & DNS Security Posture** | IANA/Nominet RDAP + Cloudflare & Google DNS-over-HTTPS (MX, SPF `v=spf1`, DMARC `_dmarc`, CAA) | `https://rdap.org/domain/{domain}`, `https://cloudflare-dns.com/dns-query` & `https://dns.google/resolve` |
| **US OFAC Sanctions** | US Treasury OFAC Specially Designated Nationals (SDN) List | `https://data.opensanctions.org/datasets/latest/us_ofac_sdn/targets.simple.csv` |
| **US Federal Recalls & Enforcement** | US FDA (`openFDA` Food/Drug Enforcement), US CPSC (`SaferProducts.gov`), US DOT NHTSA Vehicle Recalls | `https://api.fda.gov/...`, `https://www.saferproducts.gov/...`, `https://api.nhtsa.gov/...` |

---

## 15 Tools Exposed (MCP & Apify Actions)

1. `uk_sanctions_and_company_screen`: Unified end-to-end compliance & security screen across UK FCDO/OFSI sanctions, UK Charity/Companies House/GLEIF registries, EU/UK VAT, UK Postcode, RDAP+DNS/DMARC security posture, US OFAC SDN, and US FDA/CPSC/NHTSA recalls.
2. `search_uk_property_tribunal_rro_precedents`: Search UK First-tier Tribunal (Property Chamber) Rent Repayment Order (RRO) precedent rulings (OGL v3.0) by borough/keyword, region, offence type (`HMO`, `Selective Licensing`, `Unlawful Eviction`), mitigation factors, and maximum award percentage.
3. `extract_uk_scanned_pdf_clauses`: Zero-token UK scanned PDF & legal deed clause extractor (`pdftotext` + `pypdfium2` + `RapidOCR` + `FastEmbed` + ephemeral in-memory `sqlite-vec`) for Section 106 planning obligations, Companies House MR01 charge negative pledges, and Charity Independent Examiner reports.
4. `verify_eu_uk_vat`: Live European Commission VIES REST API & UK HMRC Modulo-97 VAT number verification.
5. `lookup_uk_postcode_and_council`: Resolve a UK postcode to Local Authority Council, Civil Parish, Electoral Ward, Parliamentary Constituency, and ONS GSS codes.
6. `domain_rdap_and_dns_hygiene`: Combined IANA/Nominet RDAP registration metadata and Cloudflare/Google DoH MX, SPF, DMARC, and CAA security grading.
7. `bulk_email_and_domain_hygiene`: Batch B2B RevOps domain/MX/SPF/DMARC hygiene screen for up to 100 domains with `charged_results_only=True`.
8. `audit_mcp_server_trust`: Deterministic `0-100` Pre-Connection MCP Trust, Prompt-Injection & Schema Token-Bloat Auditor.
9. `lint_apify_mcp_input_schema`: Lint and auto-fix Apify `.actor/input_schema.json` for the MCP `required`+`default` silent drop bug and maintenance prefill gaps.
10. `email_security_posture`: Deterministic DNS & Email Security audit (MX, SPF single-record RFC 7208 validation, DMARC `p=reject`/`quarantine`/`none`, `pct`, `rua`, CAA) with `0-100` score and `A-F` security grade.
11. `screen_uk_sanctions`: Standalone live UK FCDO + HM Treasury OFSI Consolidated Sanctions screening.
12. `screen_us_ofac_sanctions`: Standalone live US Treasury OFAC SDN screening.
13. `lookup_uk_public_registries`: Standalone UK Charity Commission / Companies House OrgID + GLEIF LEI lookup.
14. `us_regulatory_recall_and_enforcement_check`: Standalone US FDA, CPSC, and NHTSA recall/enforcement check.
15. `health_and_provenance`: Free (`$0.00`) health, provenance, and CAIP-2 Base `x402` payment route handshake.

---

## Running Locally

```bash
# Run pytest suite (20/20 unit + live integration tests)
.venv/bin/pytest -v

# Run as MCP server (stdio or streamable-http)
.venv/bin/python mcp_server.py --transport stdio

# Run as Apify Actor locally
.venv/bin/python -m src
```
