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
- One-click All-in-One Passive Scan runs through the shared workflow engine, catalogue-backed collector registry and adapter manager; it selects relevant passive sources by target type and records per-provider failures/skips.
- Source catalogue dialog in the OSINT Sources panel distinguishes implemented connectors from planned, licensed and manual entries; implemented API credential environment names use the `SMART_INTEL_*` convention.\n- Public website and domain TLS fetches pin the validated public DNS address to the TCP connection while preserving the original Host header and TLS SNI; redirects are not followed.
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

### Evidence vault and case audit

- Evidence tab supports opt-in encryption of evidence text and imported attachment payloads using Fernet; the random key is stored through the operating-system credential store (keyring).
- Screenshot files can be imported as evidence attachments. The application does not yet render/capture browser screenshots automatically.
- Local files can be wrapped in WARC/1.1 resource records; a public HTTP(S) URL can be fetched once and stored as a WARC response record. Redirects are not followed.
- Attachment exports verify both ciphertext and plaintext SHA-256 hashes before returning the decrypted bytes.
- Workflow lifecycle events are persisted into a hash-linked SQLite audit-event chain and can be verified from the Evidence tab.
- Important boundary: this is application-level encryption for evidence payloads and attachments, not full SQLite database encryption. Case names and metadata remain plaintext. A local hash chain detects accidental or partial edits but cannot stop an attacker with filesystem/database access from rewriting the entire chain. Use independently held signing keys and external timestamp/immutable storage for that threat model.
- Losing the OS credential-store key makes encrypted evidence unrecoverable; the UI refuses to silently replace a missing key.


- Maigret and email/phone/profile-URL identity checks now execute as explicit workflow jobs. Maigret is treated as an active multi-site operation and only runs after the analyst clicks the identity-check action; it has a 55-second subprocess deadline inside a 60-second workflow deadline.
- Adapter health counters and per-host source rate limiting are protected against concurrent collector threads.
- Pinned public website fetching retries every validated public IP address before failing; it preserves the original Host header and TLS SNI.
- Profile metadata fetches use the same pinned public fetcher rather than performing an independent DNS check followed by an unpinned HTTP request.

