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
- Interactive per-case identity/evidence graph with source-to-identifier provenance; graph nodes are leads, not identity verification.
- Explainable false-positive risk index with factor breakdown; explicitly uncalibrated and not a statistical probability.
- AI graph analysis through local Ollama (no paid API key required) or optional OpenAI, Gemini and Claude providers. Cloud-provider keys remain in OS keyring.
- Hash-linked audit journal for case/evidence additions.
- Analysis helpers for deduplication, source-type credibility, heuristic risk triage and entity extraction.
- JSON, CSV, STIX 2.1 note-bundle, DOCX and PDF export helpers; HTML export from the GUI.

## Important limitations

This is an actively developing foundation, not a finished enterprise OSINT suite. Historical WHOIS, personal email/phone lookups, company/court/sanctions sources, reverse-image search, Telegram/dark-web/forum feeds, local AI, WARC/screenshots, attachment vault, fully encrypted database, signature verification UI, multi-user roles, tasks/comments, proxy/Tor, scheduled monitoring, CLI/API, SIEM/SOAR integrations, branded report templates and signed public installers remain incomplete. See [capability matrix](../docs/osint/CAPABILITY-MATRIX.md).

Port, service and technology-stack fingerprinting is intentionally excluded. No active scanning, exploitation, account scraping, credential dumps or access-control bypass.

## Local AI analyst

Install [Ollama](https://ollama.com/), start its local service, and pull a model (for example `ollama pull qwen2.5:7b`). In the Identity Graph tab select **Ollama** and run analysis. Configure `SMART_INTEL_OLLAMA_MODEL` or `SMART_INTEL_OLLAMA_URL` to use a different local model/service. Ollama is optional; graph construction and heuristic scoring work without it. OpenAI/Gemini/Claude remain optional cloud providers.

## Risk score interpretation

The displayed 0–100 value is a conservative, explainable triage index, not a calibrated probability. It must not be read as “55% chance of false positive.” The current graph links extracted public identifiers to the evidence records where they appeared. It does not merge accounts into people or prove ownership. A calibrated probability would require a representative labeled dataset, held-out validation and calibration metrics.

## Packaging

See [BUILDING.md](BUILDING.md). Build separately on each target OS; PyInstaller is not a cross-compiler. CI build artifacts are not yet signed public releases.
