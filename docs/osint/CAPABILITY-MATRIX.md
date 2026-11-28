# Capability matrix and roadmap

Status reflects code in the current repository, not a marketing checklist.

| Requested capability | Status | Notes |
|---|---|---|
| Subdomain enumeration | Partial | CT names available; no DNS brute force or active enumeration |
| Certificate transparency | Initial connector | crt.sh |
| Passive DNS | Initial connector | SecurityTrails key required |
| WHOIS history | Planned | Base RDAP exists; historical provider adapter absent |
| Shodan / Censys / VirusTotal / AbuseIPDB / urlscan / OTX / MISP | Initial connectors | Existing provider data/search APIs; keys/quotas apply |
| Breach/leak data | Safe workflow only | Authorized notification guidance; no dump retrieval |
| Username lookup | Partial | Public profile reference links only |
| Email / phone / social media | Not implemented | No private-person dossiers or sensitive-attribute inference |
| Reverse image search / EXIF / geolocation | Not implemented | Future user-provided image metadata module |
| Company / news / court / sanctions | Partial | GDELT news; official registry adapters pending |
| Dark web / Telegram / forums | Not implemented | Future lawful public/API feeds only |
| Wayback | Initial connector | CDX public endpoint |
| Port/service/tech-stack fingerprinting | **Excluded by design** | No active scanning or fingerprinting |
| Entity relationship graph | Initial UI | Interactive per-case graph links extracted public identifiers to source evidence; no automatic person merging or identity proof |
| Timeline | Implemented as table | No chart/timeline visualization |
| Correlation/deduplication | Partial | Evidence-linked identifier extraction; exact content fingerprint dedup helper; relationship correlation remains conservative |
| Risk/reputation scoring | Initial UI | Explainable 0–100 false-positive triage index; explicitly uncalibrated, not a probability |
| Source credibility | Partial | Source-type heuristic only |
| Local/offline AI | Initial integration | Optional Ollama analysis of graph/evidence; cloud providers remain optional |
| Chain of custody/audit | Partial | Hash-linked JSONL journal with a verification action; local file access can still permit full rewrite and re-hash |
| Tamper-evident hashes/signatures | Partial | SHA-256 and hash-chain checks; signing helper is not yet a trusted signing workflow or externally anchored checkpoint |
| Screenshots / WARC | Not implemented | Capture pipeline pending |
| Encrypted storage | Not implemented | SQLite case database remains plaintext; Fernet helper does not encrypt database pages or manage keys/migrations |
| Attachments/file import | Not implemented | Attachment vault pending |
| Multi-user roles/shared cases | Not implemented | Local single-user app |
| Comments/tasks/assignment | Not implemented | Collaboration layer pending |
| Proxy/VPN/Tor | Not implemented | No routing/proxy UI |
| Rate limits | Partial | Per-host pacing; provider quotas still apply |
| Scheduled monitoring | Not implemented | Scheduler/alerting pending |
| API/CLI/automation | Not implemented | Python helper modules only |
| SIEM/SOAR/ticketing | Not implemented | Integrations pending |
| PDF / Word / STIX / CSV / JSON | Partial | Export actions are wired in the desktop UI; STIX currently emits evidence notes and typed URL/domain/public IPv4 Indicators extracted from evidence; format validation and interoperability testing remain |
| Branded templates | Not implemented | Template engine pending |
| IOC sharing | Partial | Typed STIX 2.1 Indicator objects are emitted for extracted URL, domain and globally routable IPv4 values; extracted values are observations, not verdicts |
| Test coverage | Expanded, CI validation pending | Unit tests cover storage, IP restrictions, audit and exports; new STIX newline regression test added; provider network tests and independent security testing remain |
| Signed releases/installers | Not implemented | CI build artifacts only |
| Prebuilt releases | Not yet published | CI artifacts are not a stable public release |
| Documentation | Updated | OSINT install, usage, sources, security and matrix |

## Suggested delivery sequence

1. Stabilize source adapters and broaden offline/unit tests.
2. Complete evidence vault: attachments, WARC, screenshot capture, encrypted DB and audit verification/signatures.
3. Expand graph extraction/correlation, add timeline filters and validate risk scoring with a representative labeled dataset.
4. Add official company/sanctions/court adapters and authorized breach notifications.
5. Add PDF/report templates and typed STIX IOC objects.
6. Add local AI, scheduled jobs, CLI/API and SIEM/ticketing integrations.
7. Add team collaboration, role permissions and shared-case backend.
8. Produce signed installers, checksums, SBOM and public releases.
