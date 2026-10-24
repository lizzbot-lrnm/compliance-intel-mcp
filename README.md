# UK & US Compliance, Sanctions, Registry, DNS Security & Recall Intelligence (`compliance-intel-mcp`)

Deterministic, **zero-LLM-cost** compliance and security screening engine that runs both as:
1. **An Apify Actor** (`uk-us-compliance-mcp-actor`) writing structured compliance reports to the default Apify dataset.
2. **An MCP Server (`mcp_server.py`) + `mcpize.yaml`** with native `x402` USDC on Base pay-per-call settlement (`0.02` USDC/call to `0xfe4404ee088a741DC6F62d4132e21E14B1912940`).

Every check queries **live government and public authority endpoints** (zero mocked data), embeds **verbatim source URLs** and **ISO-8601 UTC retrieval timestamps**, and **fails closed** on upstream network or parsing errors.

---

## Live Public Data Sources Queried

| Domain | Official / Public Authority Source | Endpoint |
| :--- | :--- | :--- |
| **UK Sanctions (FCDO)** | UK Foreign, Commonwealth & Development Office Sanctions List (OpenSanctions Live Standardized Feed) | `https://data.opensanctions.org/datasets/latest/gb_fcdo_sanctions/targets.simple.csv` |
| **UK Financial Sanctions (OFSI)** | UK HM Treasury Office of Financial Sanctions Implementation Consolidated List | `https://ofsistorage.blob.core.windows.net/publishlive/2022format/ConList.csv` |
| **UK Charity & Company Registry** | UK Charity Commission / Companies House Cross-Reference (FindThatCharity Reconciliation & OrgID JSON API) | `https://findthatcharity.uk/reconcile` & `https://findthatcharity.uk/orgid/{id}.json` |
| **Global & UK Corporate LEI** | Global Legal Entity Identifier Foundation (GLEIF) API v1 (with UK Companies House `RA000585` / Charity `RA000589` validation) | `https://api.gleif.org/api/v1/lei-records` |
| **Email & DNS Security Posture** | Cloudflare & Google DNS-over-HTTPS (MX, SPF `v=spf1`, DMARC `_dmarc`, CAA) | `https://cloudflare-dns.com/dns-query` & `https://dns.google/resolve` |
| **US OFAC Sanctions** | US Treasury OFAC Specially Designated Nationals (SDN) List | `https://data.opensanctions.org/datasets/latest/us_ofac_sdn/targets.simple.csv` |
| **US Federal Recalls & Enforcement** | US FDA (`openFDA` Food/Drug Enforcement), US CPSC (`SaferProducts.gov`), US DOT NHTSA Vehicle Recalls | `https://api.fda.gov/...`, `https://www.saferproducts.gov/...`, `https://api.nhtsa.gov/...` |

---

## Tools Exposed (MCP & Apify Actions)

1. `uk_sanctions_and_company_screen`: Unified end-to-end compliance & security screen across UK FCDO/OFSI sanctions, UK Charity/Companies House/GLEIF registries, DNS & DMARC security posture, US OFAC SDN, and US FDA/CPSC/NHTSA recalls.
2. `email_security_posture`: Deterministic DNS & Email Security audit (MX, SPF single-record RFC 7208 validation, DMARC `p=reject`/`quarantine`/`none`, `pct`, `rua`, CAA) with `0-100` score and `A-F` security grade.
3. `screen_uk_sanctions`: Standalone live UK FCDO + HM Treasury OFSI Consolidated Sanctions screening.
4. `screen_us_ofac_sanctions`: Standalone live US Treasury OFAC SDN screening.
5. `lookup_uk_public_registries`: Standalone UK Charity Commission / Companies House OrgID + GLEIF LEI lookup.
6. `us_regulatory_recall_and_enforcement_check`: Standalone US FDA, CPSC, and NHTSA recall/enforcement check.

---

## Running Locally

```bash
# Run pytest suite (unit + live integration tests)
.venv/bin/pytest -v

# Run as MCP server (stdio or streamable-http)
.venv/bin/python mcp_server.py --transport stdio

# Run as Apify Actor locally
.venv/bin/python -m src
```
