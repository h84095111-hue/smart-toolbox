# OSINT source integrations

Smart Intel uses passive/public-source APIs and user-configured services. Availability, rate limits and permitted use depend on each provider's terms and API plan.

| Source | Function | Key |
|---|---|---|
| crt.sh | Certificate transparency names | No |
| Internet Archive CDX | Wayback captures | No |
| VirusTotal | Domain reputation and analysis summary | Yes |
| AbuseIPDB | Public IP abuse reports | Yes |
| urlscan.io | Existing public scan search | Usually no for public search; quotas apply |
| AlienVault OTX | Domain pulse summary | Yes |
| Shodan | Existing indexed host record | Yes |
| Censys | Existing indexed host record | Yes |
| SecurityTrails | Passive DNS history | Yes |
| MISP | Exact IOC lookup against a configured instance | Yes |
| GDELT | Public news results | No |
| Public profile links | Username search starting points | No |
| Breach workflow | Authorized service guidance only | No |

## Configure keys

Use the in-app **AI provider settings** dialog. Keyring service names: `virustotal`, `abuseipdb`, `otx`, `shodan`, `censys`, `securitytrails`, and `misp`. Environment variables are supported by adapters, for example `SMART_INTEL_VIRUSTOTAL_API_KEY`.

MISP requires an HTTPS base URL in the OSINT Sources panel. The connector performs an exact IOC attribute search only.

## Not currently connected

Historical WHOIS beyond base RDAP, authenticated HIBP breach queries, OpenCorporates, OpenSanctions, official court registries, Telegram bot/API feeds, RSS/forum feeds and social-platform APIs need additional source-specific adapters and terms review. Username lookup currently builds public profile reference URLs only.

## Safety boundaries

- No port scanning, service fingerprinting, exploit checks or active probing.
- No credential stuffing, password dumps, account takeover or private-account scraping.
- No illicit dark-web credential marketplace access.
- No inference that a username/profile belongs to a particular person.
- Public data may be inaccurate, stale or restricted by licensing; validate provenance and reuse rights.
