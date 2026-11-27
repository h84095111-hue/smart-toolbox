# Smart Intel user guide

## Investigation workflow

1. Start Smart Intel and create an investigation case.
2. Use **Collect** for the built-in domain, public-IP and website lookups.
3. Use **OSINT Sources** for certificate transparency, Wayback, threat-intelligence providers, passive DNS history, news and MISP exact-IOC searches.
4. Add useful findings to the active case.
5. Review the **Evidence & Timeline** table. Each row records source, URL, observation time and confidence.
6. Use **AI Analyst** to summarize the evidence. The selected provider receives the evidence text; only send material you are authorized to disclose.
7. Export the case as HTML. JSON, CSV, STIX and DOCX export helpers are also available to Python integrations.

## Provider keys

Open **AI provider settings** and enter only the provider keys you intend to use. Keys are saved through keyring. API calls may incur third-party charges. Never commit keys to GitHub.

## OSINT Sources panel

Choose a source, enter a domain, public IP, URL, username or IOC, and run the lookup. The result is displayed before you add it to the case. MISP requires an HTTPS instance URL and a configured API key.

- crt.sh: historical certificate names; not proof that a hostname is live.
- Wayback: archived public page captures; archives can be incomplete or stale.
- VirusTotal, AbuseIPDB, OTX, Shodan and Censys: provider-reported intelligence, not ground truth.
- Shodan/Censys: queries existing indexed observations only; no scan is initiated.
- SecurityTrails: passive DNS history, subject to API entitlement.
- GDELT: public news references; reporting is secondary-source material.
- Username reference links: starting points only; they do not verify identity or account ownership.
- Breach workflow: points to verified-domain/authorized notification services; it does not query stolen credential dumps.

## Evidence quality

Keep original URLs, timestamps and source names. Treat provider labels and risk scores as leads. Corroborate important claims independently. Distinguish direct observations from inference and record uncertainty.

## Current limitations

The timeline is a table, not a visual timeline. Entity extraction and scoring are helper functions, not a full interactive graph. WARC capture, screenshot capture, attachment import, encrypted case database, signature verification UI, team collaboration, scheduled monitoring and SIEM/SOAR integrations are not yet implemented.
