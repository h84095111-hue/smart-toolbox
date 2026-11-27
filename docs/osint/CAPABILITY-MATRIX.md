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
| Entity relationship graph | Partial | Entity extraction helper; interactive graph UI pending |
| Timeline | Implemented as table | No chart/timeline visualization |
| Correlation/deduplication | Partial | Exact content fingerprint dedup helper |
| Risk/reputation scoring | Partial | Transparent heuristic helper, not calibrated |
| Source credibility | Partial | Source-type heuristic only |
| Local/offline AI | Planned | Current AI providers are remote APIs |
| Chain of custody/audit | Partial | Hash-linked JSONL journal; verification UI pending |
| Tamper-evident hashes/signatures | Partial | Hash chain, SHA-256 and signing helpers |
| Screenshots / WARC | Not implemented | Capture pipeline pending |
| Encrypted storage | Partial | Fernet helper only; SQLite is not automatically encrypted |
| Attachments/file import | Not implemented | Attachment vault pending |
| Multi-user roles/shared cases | Not implemented | Local single-user app |
| Comments/tasks/assignment | Not implemented | Collaboration layer pending |
| Proxy/VPN/Tor | Not implemented | No routing/proxy UI |
| Rate limits | Partial | Per-host pacing; provider quotas still apply |
| Scheduled monitoring | Not implemented | Scheduler/alerting pending |
| API/CLI/automation | Not implemented | Python helper modules only |
| SIEM/SOAR/ticketing | Not implemented | Integrations pending |
| PDF / Word / STIX / CSV / JSON | Partial | DOCX, STIX note bundle, CSV and JSON helpers; PDF pending |
| Branded templates | Not implemented | Template engine pending |
| IOC sharing | Partial | STIX note bundle; typed STIX Indicator objects pending |
| Test coverage | Expanded | Unit tests for storage, IP restrictions, audit, analysis and exports; provider network tests pending |
| Signed releases/installers | Not implemented | CI build artifacts only |
| Prebuilt releases | Not yet published | CI artifacts are not a stable public release |
| Documentation | Updated | OSINT install, usage, sources, security and matrix |

## Suggested delivery sequence

1. Stabilize source adapters and broaden offline/unit tests.
2. Complete evidence vault: attachments, WARC, screenshot capture, encrypted DB and audit verification/signatures.
3. Build graph UI, source correlation, timeline table filters and explainable risk scoring.
4. Add official company/sanctions/court adapters and authorized breach notifications.
5. Add PDF/report templates and typed STIX IOC objects.
6. Add local AI, scheduled jobs, CLI/API and SIEM/ticketing integrations.
7. Add team collaboration, role permissions and shared-case backend.
8. Produce signed installers, checksums, SBOM and public releases.
