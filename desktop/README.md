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

## Current limitations

This remains an actively developing local desktop application, not a complete enterprise OSINT platform. The following areas still require additional work or external deployment:

- Reverse-image matching is analyst-operated: Smart Intel opens Google Lens, Bing Visual Search or TinEye; it does not upload images to those providers automatically or use a dedicated reverse-search API.
- SQLCipher, Pillow and Playwright are optional dependencies. SQLCipher key loss makes the database unrecoverable; the encryption migration deliberately retains a plaintext backup until the operator validates recovery and removes it securely.
- Signed exports prove that the manifest matches the embedded Ed25519 key. The signer is authenticated only when the key fingerprint is trusted independently. RFC 3161 timestamps are optional and only verified when a trusted TSA CA certificate is supplied.
- Multi-user accounts and case membership apply to this local SQLite store. This is not a networked multi-tenant server, identity federation or remote collaboration service.
- Scheduled monitoring runs only while the Smart Intel desktop application is open. It does not run as a Windows service, system daemon or hosted scheduler.
- Proxy routing is opt-in. Tor must already be running and expose a SOCKS5 listener; VPNs are managed by the operating system. A proxy is not an anonymity guarantee and pinned-target lookups resolve the destination locally before connecting.
- Browser screenshot capture validates public URLs and subrequests, but a browser and proxy are complex network clients; do not treat this as a hardened browser sandbox for untrusted URLs.
- CourtListener search covers published opinions, not every docket or court record. OpenSanctions results are candidate matches, never a legal determination; confirm names, dates, identifiers and primary sources. OpenSanctions business use requires checking its paid licensing terms; the connector must not be treated as a free commercial screening service.
- OpenCorporates coverage and HIBP lookups depend on current API access, subscription, provider limits and terms.
- Historical WHOIS, broad social account discovery, Telegram/dark-web/forum collection, remote team hosting, task assignment/comments, SIEM/SOAR and public signed installers remain out of scope or planned.

No active scanning, exploitation, account-login attempts, credential-dump retrieval, challenge bypass or access-control bypass is provided.

## Optional capabilities setup

Install optional packages only for features you intend to enable:

```bash
python -m pip install -r requirements-optional.txt
python -m playwright install chromium
```

- **Proxy / Tor:** Open AI & network settings and enter an HTTP proxy, HTTPS proxy or SOCKS5 URL such as `socks5://127.0.0.1:9050`. Start/configure Tor separately. The app displays the selected route. VPN routing is managed by the OS, not Smart Intel.
- **HIBP:** Add a Have I Been Pwned API subscription key in provider settings. A lookup checks only the exact email address entered and saves breach metadata; it does not retrieve passwords or credential dumps. Results include the required provider attribution.
- **Company / court / sanctions:** Configure OpenCorporates, CourtListener and OpenSanctions keys in provider settings. Select the corresponding source in the OSINT Sources tab and enter a company name or record query. OpenSanctions uses candidate matching and must be manually reviewed.
- **Images:** The Evidence tab can inspect local EXIF/GPS metadata, SHA-256 and perceptual hashes. Reverse-image portals open separately; the analyst decides whether to upload an image. Local file comparison and matching do not establish subject identity. HIBP attribution is included in result evidence under CC BY 4.0; provider terms still apply.
- **Screenshots:** Enable the evidence vault, then use Capture browser screenshot. Playwright Chromium is required. The captured PNG is imported into the encrypted attachment vault.
- **Full DB encryption:** Enable full SQLCipher encryption from Evidence & Timeline. Keep the adjacent `.plaintext-backup` in a safe recovery location until you've verified the encrypted database. The SQLCipher key is stored in the OS credential store.
- **Signed export:** Use Reports → Export signed bundle. An RFC 3161 TSA URL is optional; to mark the timestamp verified, provide the TSA trust CA when prompted. Verify a signer fingerprint from an independent trusted channel.
- **Accounts / case sharing:** The first launch creates the first administrator. The administrator creates local analyst/viewer accounts and shares cases. Account access is enforced inside the desktop application; protect the local database and device with OS-level controls.
- **Scheduled monitoring:** Create schedules from the Monitoring tab. The app must remain open to execute them. Schedules only run passive source checks for a domain, public URL or globally routable IP and are stored locally.

The provider adapters use current API endpoints, but external service availability, access, licensing, authentication requirements and rate limits remain controlled by each provider.

## Local AI analyst

Install [Ollama](https://ollama.com/), start its local service, and pull a model (for example `ollama pull qwen2.5:7b`). In the Identity Graph tab select **Ollama** and run analysis. Configure `SMART_INTEL_OLLAMA_MODEL` or `SMART_INTEL_OLLAMA_URL` to use a different local model/service. Ollama is optional; graph construction and heuristic scoring work without it. OpenAI/Gemini/Claude remain optional cloud providers.

## Risk score interpretation

The displayed 0–100 value is a conservative, explainable triage index, not a calibrated probability. It must not be read as “55% chance of false positive.” The current graph links extracted public identifiers to the evidence records where they appeared. It does not merge accounts into people or prove ownership. A calibrated probability would require a representative labeled dataset, held-out validation and calibration metrics.

## Packaging

See [BUILDING.md](BUILDING.md). Build separately on each target OS; PyInstaller is not a cross-compiler. CI build artifacts are not yet signed public releases.

### Evidence vault and case audit

- Evidence tab supports opt-in encryption of evidence text and imported attachment payloads using Fernet; the random key is stored through the operating-system credential store (keyring).
- Public browser screenshots can be captured with Playwright Chromium and are imported into the encrypted attachment vault when it is enabled; screenshots can also be imported from disk.
- Local files can be wrapped in WARC/1.1 resource records; a public HTTP(S) URL can be fetched once and stored as a WARC response record. Redirects are not followed.
- Attachment exports verify both ciphertext and plaintext SHA-256 hashes before returning the decrypted bytes.
- Workflow lifecycle events are persisted into a hash-linked SQLite audit-event chain and can be verified from the Evidence tab.
- Important boundary: full-database SQLCipher encryption is now an optional migration. Until SQLCipher is enabled, this is application-level encryption for evidence payloads and attachments, not full database encryption. The migration retains a plaintext backup; case metadata is protected only after migration. A local hash chain detects accidental or partial edits but cannot stop an attacker with filesystem/database access from rewriting the entire chain. Use independently held signing keys and external timestamp/immutable storage for that threat model.
- Losing the OS credential-store key makes encrypted evidence unrecoverable; the UI refuses to silently replace a missing key.


- All-in-One scans, selected-source lookups, Maigret and email/phone/profile-URL identity checks now execute as workflow jobs. Maigret is treated as an active multi-site operation and only runs after the analyst clicks the identity-check action; it has a 55-second subprocess deadline inside a 60-second workflow deadline.
- Adapter health counters and per-host source rate limiting are protected against concurrent collector threads.
- Pinned public website fetching retries every validated public IP address before failing; it preserves the original Host header and TLS SNI.
- Profile metadata fetches use the same pinned public fetcher rather than performing an independent DNS check followed by an unpinned HTTP request.

