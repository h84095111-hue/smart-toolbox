# Smart Intel — AI OSINT Workstation

**A cross-platform, AI-assisted OSINT desktop application built with Python + PyQt6.** Organize public-source research into cases, correlate findings, and analyze evidence with OpenAI, Gemini or Claude.

> This project replaces the original browser-based Smart Toolbox. The primary product is now the PyQt6 desktop app in [desktop/](desktop/).

## Desktop interface

![Smart Intel desktop concept preview](desktop/assets/smart-intel-preview.svg)

*Illustrative concept artwork only — not a screenshot of the running application. A real screenshot is still required before release.*

## Available now

- PyQt6 desktop shell with a refined dark-first interface, local SQLite cases, evidence table and AI analyst.
- One-click **All-in-One Passive Scan**: auto-detects domain, public IP, URL, username or email, runs the relevant built-in collectors and configured OSINT providers, and keeps going when individual providers fail.
- Passive DNS/RDAP/TLS and public website metadata collection.
- Optional provider lookups: crt.sh certificate transparency, Wayback CDX, VirusTotal, AbuseIPDB, urlscan.io, AlienVault OTX, Shodan existing-host data, Censys existing-host data, SecurityTrails passive DNS, GDELT news and user-configured MISP exact-IOC search.
- Public username profile reference links (no account scraping or identity verification).
- Authorized breach-check workflow guidance; no stolen credential dumps.
- Interactive evidence/identity graph with provenance, same-record identifier correlation, mouse-wheel zoom and drag navigation.\n- Evidence-derived explainable false-positive caution factors; still an uncalibrated heuristic, never a statistical probability.\n- Local Ollama and cloud AI analysis receive the structured graph, risk factors and evidence context.\n- Passive collection CLI: `python -m smartintel.cli <target> --output findings.json`.
- Explainable false-positive risk index (uncalibrated heuristic, not a statistical probability).
- Evidence deduplication, heuristic source credibility and transparent triage scoring helpers.
- Hash-linked JSONL audit journal, SHA-256 attachment hashing, optional Fernet encryption and Ed25519 signing helpers.
- JSON, CSV, STIX 2.1 note-bundle and DOCX export helpers; existing HTML report export.
- Automated tests for core safety, audit integrity, analysis helpers and exports.

## Quick start

```bash
git clone https://github.com/h84095111-hue/SMART-INTEL.git
cd SMART-INTEL/desktop
python -m venv .venv
# Windows: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Run passive collection from the terminal (from the `desktop/` directory):

```bash
python -m smartintel.cli example.com --output findings.json
```

Python 3.10+ is recommended. Configure AI and OSINT provider keys in **AI provider settings**. Third-party API usage may be billed separately.

## Build

- Windows: `build_windows.bat`
- macOS: `./build_macos.sh`
- Linux: `./build_linux.sh`

Build on the target OS. See [desktop/BUILDING.md](desktop/BUILDING.md). CI runs tests and creates per-platform build artifacts; public signed installers are not yet published.

## Capability status

| Area | Status |
|---|---|
| CT logs, Wayback, passive DNS and listed threat-intel APIs | Initial passive connectors available; provider keys/quotas apply |
| WHOIS history, username references, news | Partial; provider-specific history and official source adapters remain |
| Email/phone and social lookups | Partial; conservative public identifier extraction from collected evidence, not subscriber/account verification |
| Court, company and sanctions records | Planned; source-specific official adapters needed |
| Dark web, Telegram and forums | Not implemented; only future lawful public/API integrations |
| Port/service/tech-stack fingerprinting | **Excluded by design** |
| Entity graph, correlation and risk scoring | Interactive evidence-to-identifier graph; explainable uncalibrated risk index; no automatic person merging or identity proof |
| Timeline | Evidence table only |
| Chain of custody | Hash-linked audit journal integrated for case/evidence additions; verification UI pending |
| Encryption, signatures, attachments, WARC and screenshots | Helpers only for encryption/signatures/hashing; full evidence vault and capture pipeline pending |
| Team accounts, roles, shared cases, tasks and comments | Not implemented |
| Proxy/Tor, scheduling and continuous monitoring | Not implemented |
| CLI/API, SIEM/SOAR/ticketing | Not implemented |
| PDF, JSON, CSV, STIX, DOCX, HTML | Export helpers available; app export UI and branded templates pending |
| Prebuilt releases and signed installers | Not yet published |

See [OSINT capability matrix](docs/osint/CAPABILITY-MATRIX.md) and [source integrations](docs/osint/SOURCES.md).

## Responsible use

Designed for lawful, authorized research of public information. No login bypass, exploitation, active port scanning, private-account scraping or access to non-public systems. Shodan and Censys functions query existing provider observations only; they do not initiate scans. Respect provider terms, rate limits, privacy law and authorization. Do not submit personal identifiers unless you have a lawful basis. AI outputs and reputation scores are triage aids, not verified facts.

Cases are stored locally in `~/.smart-intel/data/`. API keys are stored through the OS credential store when available. Evidence sent to an AI provider is transmitted to that provider's API.

## Documentation

- [Install and run](docs/INSTALLATION.md)
- [User guide](docs/USAGE.md)
- [Provider setup](docs/osint/SOURCES.md)
- [Capability matrix and roadmap](docs/osint/CAPABILITY-MATRIX.md)
- [Security and evidence handling](docs/osint/SECURITY.md)

## License

MIT — see [LICENSE](LICENSE).


## Graph and identity-analysis safeguards

The desktop graph now debounces text filtering, calculates filters/clusters/layout in a worker thread, and uses a component-aware linear-time layout fallback for graphs above 180 nodes. Smaller graphs use the force-directed layout. Semantic identity hints are captured by the built-in website collector before it reduces HTML to text; the graph also accepts structured semantic identifier records from evidence JSON.

Phone extraction accepts semantic attributes only when their names contain exact tokens such as `telephone`, `phone`, or `tel`, and requires at least eight digits. This is a format filter, not phone-number validation or ownership verification.

False-positive triage is scoped to the selected graph identifier. An unrelated email elsewhere in the same evidence record cannot lower the selected username or phone node's risk. Evidence age uses a rolling 365-day window. Distinct source labels are not assumed to be independent sources, and the index remains an uncalibrated heuristic.

Email, phone, and profile-metadata identity-check observations are now saved to the active case as evidence, in addition to Maigret candidate-profile findings. These checks still do not establish mailbox existence, phone subscriber identity, or account ownership.

## Remaining work

The workflow engine, adapter manager and source catalogue still need app integration. Screenshots/WARC capture, encrypted case storage, opt-in proxy/Tor routing, real account discovery and authorized breach/corporate/court-data integrations, graph editing/export, timeline filters, multi-user roles, scheduling, SIEM integration, signed releases and UI automation remain planned or incomplete. Do not treat the application as a finished or production-hardened investigation platform.
