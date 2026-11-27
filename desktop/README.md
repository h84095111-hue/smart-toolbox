# Smart Intel — PyQt6 OSINT desktop

This is the primary application. Smart Intel is a cross-platform desktop workspace for lawful, passive public-source research.

## Run

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Python 3.10+ recommended. Install development dependencies and run tests with:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Current desktop features

- Dark-first PyQt6 interface, local SQLite investigation cases and evidence table.
- One-click All-in-One Passive Scan for domains, public IPs and URLs; automatically selects relevant passive sources and records per-provider failures/skips.
- Passive DNS/RDAP/TLS and public website metadata.
- OSINT Sources panel: crt.sh, Wayback, VirusTotal, AbuseIPDB, urlscan.io, OTX, Shodan/Censys existing host metadata, SecurityTrails passive DNS, GDELT, MISP exact IOC search, public username reference links and authorized breach-check guidance.
- OpenAI, Gemini and Claude analysis; OSINT and AI API keys stored with keyring.
- Hash-linked audit journal for case/evidence additions.
- Analysis helpers for deduplication, source-type credibility, heuristic risk triage and entity extraction.
- JSON, CSV, STIX 2.1 note-bundle, DOCX and PDF export helpers; HTML export from the GUI.

## Important limitations

This is an actively developing foundation, not a finished enterprise OSINT suite. The timeline is a table; graph helpers are not a graph UI. Historical WHOIS, personal email/phone lookups, company/court/sanctions sources, reverse-image search, Telegram/dark-web/forum feeds, local AI, WARC/screenshots, attachment vault, fully encrypted database, signature verification UI, multi-user roles, tasks/comments, proxy/Tor, scheduled monitoring, CLI/API, SIEM/SOAR integrations, branded report templates and signed public installers remain incomplete. See [capability matrix](../docs/osint/CAPABILITY-MATRIX.md).

Port, service and technology-stack fingerprinting is intentionally excluded. No active scanning, exploitation, account scraping, credential dumps or access-control bypass.

## Packaging

See [BUILDING.md](BUILDING.md). Build separately on each target OS; PyInstaller is not a cross-compiler. CI build artifacts are not yet signed public releases.
