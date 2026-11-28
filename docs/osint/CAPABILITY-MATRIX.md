# Capability matrix and roadmap

Status reflects code in this branch, not a marketing checklist.

| Requested capability | Status | Notes |
|---|---|---|
| Subdomain enumeration | Partial | Certificate-transparency results; no DNS brute force or active enumeration |
| Certificate transparency | Implemented | crt.sh passive query |
| Passive DNS / RDAP / TLS | Implemented | Existing passive connectors; API quotas and source coverage apply |
| WHOIS history | Planned | Historical WHOIS source adapter still absent |
| Shodan / Censys / VirusTotal / AbuseIPDB / urlscan / OTX / SecurityTrails / MISP | Implemented | API credentials, subscriptions and quotas apply |
| HIBP integration | Implemented | Exact analyst-supplied email breach metadata lookup; subscription key required; no password/dump retrieval |
| Corporate records | Implemented | OpenCorporates company search; API token and provider terms apply |
| Court APIs | Partial | CourtListener published-opinion search; not complete docket or court-record coverage |
| Sanctions integrations | Partial | OpenSanctions candidate search; verify identity and licensing, not a legal decision |
| Username lookup | Partial | Public username reference sources and analyst-triggered Maigret checks; no identity proof |
| Email / phone | Partial | Format, DNS and provider-supported checks; HIBP is opt-in exact email lookup; no mailbox access or credential dumps |
| Reverse image search / EXIF / geolocation | Partial | Local EXIF/GPS/SHA-256/dHash; external reverse-image portal handoff is manual, no automatic image upload/provider API |
| Dark web / Telegram / forums | Planned | No access-control bypass, credential dumps or illicit marketplace collection |
| Wayback | Implemented | CDX public endpoint |
| Port/service/tech-stack fingerprinting | **Excluded by design** | No active scanning or fingerprinting |
| Entity relationship graph | Implemented | Evidence-backed graph, analyst-added leads, explicit persisted alias merges; not automatic person resolution |
| Timeline | Implemented | Evidence date-range and text filters; no visual timeline chart |
| Correlation/deduplication | Partial | Evidence-linked identifiers and conservative co-observation edges |
| Risk/reputation scoring | Partial | Explainable 0–100 false-positive triage index; uncalibrated and not a probability |
| Source credibility | Partial | Source-type heuristics; no calibrated reliability model |
| Local/offline AI | Implemented | Optional Ollama graph/evidence analysis; cloud providers remain optional |
| Chain of custody/audit | Partial | Hash-linked SQLite event history and evidence hashing; local owner with full database access can rewrite local history |
| Tamper-evident signatures | Implemented | Ed25519 signed manifest bundles; signer identity requires independently trusted public-key fingerprint |
| Trusted timestamps | Partial | Optional RFC 3161 TSA request; status is only verified when an explicit trusted CA is supplied |
| Screenshots / WARC | Implemented | Playwright Chromium public-page screenshot capture; screenshot saved as encrypted attachment when vault enabled; WARC file and one-response URL capture |
| Encrypted storage | Implemented | Fernet evidence/attachments plus optional SQLCipher full-database page encryption; SQLCipher package/keyring required; plaintext backup retained after migration |
| Attachments/file import | Implemented | Evidence vault import/export with hash verification |
| Multi-user roles/shared cases | Partial | Local accounts with PBKDF2 password hashes and admin/analyst/viewer roles; case membership/sharing on local SQLite; no remote collaboration server |
| Graph manual edits / alias merging | Implemented | Manual annotated leads and explicit analyst-confirmed alias decisions; evidence provenance retained |
| Timeline filters | Implemented | Date-from/date-to and full-text evidence search |
| Generic forced cancellation | Implemented | Collectors run in isolated worker processes; timeout/cancel terminates process trees where supported; trusted plugins are not a security sandbox |
| Proxy / VPN / Tor | Partial | Optional HTTP/HTTPS CONNECT and SOCKS5 proxy routing; Tor must already run as a SOCKS endpoint; VPN is controlled by OS; not anonymity |
| Rate limits | Implemented | Thread-safe per-host pacing; provider quotas still apply |
| Scheduled monitoring | Partial | Persistent local schedules run passive scans while the desktop app is open; no background service or hosted scheduler |
| API/CLI/automation | Partial | Python helpers/CLI exist; no stable public API contract |
| SIEM/SOAR/ticketing | Planned | Not implemented |
| PDF / Word / STIX / CSV / JSON | Partial | Existing export helpers; signed bundle added; interoperability and validation work remains |
| Branded templates | Planned | Template engine pending |
| Signed releases/installers | Planned | CI packaging artifacts are not public signed releases |
| Tests | Expanded; CI validation pending | New offline tests cover cancellation, accounts, schedules, graph aliasing, proxies, HIBP and signed exports; cross-platform CI must be green before release |

## Optional dependencies

- `Pillow`: local image metadata and perceptual hash analysis.
- `Playwright` plus `python -m playwright install chromium`: browser screenshot capture.
- `sqlcipher3-binary`: full SQLite database page encryption.
- `PySocks`: SOCKS5 routing.
- `cloudpickle`: process-isolated workflow callables.

Install the opt-in desktop features with `python -m pip install -r desktop/requirements-optional.txt` from the repository root only if using the relevant features (or install from the `desktop` directory).

## Remaining delivery work

1. Add an optional dedicated reverse-image provider API and define safe upload/retention controls.
2. Expand court coverage beyond published opinions; add registry-specific national company and official sanctions list adapters.
3. Add signed verification workflows with independently distributed public-key trust and production TSA trust bundles.
4. Move case collaboration and monitoring to a hardened shared service if remote multi-user use is required.
5. Add background scheduling service, multi-instance job locks, notifications and audit retention controls.
6. Complete security review, cross-platform package matrix, dependency/SBOM generation, signed release artifacts and external penetration testing.
