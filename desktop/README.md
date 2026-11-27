# Smart Intel — AI OSINT Workstation

Cross-platform PyQt6 desktop app for authorized, passive open-source intelligence research. It combines public-source collection, case management, evidence tracking, optional multi-provider AI analysis and HTML reporting.

## Features in this foundation

- **Cases:** create and switch investigations; case and evidence data are stored locally in SQLite.
- **Domain intelligence:** system DNS resolution, ICANN RDAP registration summary and TLS certificate metadata.
- **Public IP intelligence:** public RDAP registration data and reverse DNS. Private, loopback and other non-global addresses are rejected.
- **Website intelligence:** public page title, description, selected security headers, outbound links and bounded text excerpt.
- **AI analyst:** optional OpenAI, Gemini and Claude API integrations. Keys are saved in the operating system credential store via keyring.
- **Evidence timeline:** source, observation timestamp, URL and confidence are stored for each finding.
- **Reports:** export a self-contained HTML evidence report.

## Run from source

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Configure API keys from **AI provider settings**. Provider API usage is billed separately.

## Build desktop packages

Build on the target OS and architecture; PyInstaller does not cross-compile.

- Windows: `build_windows.bat`
- macOS: `./build_macos.sh` (sign and notarize before public distribution)
- Linux: `./build_linux.sh`

See [BUILDING.md](BUILDING.md).

## Responsible-use scope

Smart Intel is designed for passive research of public information and systems you own or are authorized to assess. It does not attempt authentication, bypass access controls, exploit systems, perform port scanning, enumerate private accounts or retrieve non-public data. Respect site terms, privacy laws, rate limits and applicable policies. A public-source result is not proof of identity, ownership, compromise or wrongdoing. Validate findings independently and document uncertainty.

Cases are stored locally in `~/.smart-intel/data/`. API keys use the OS credential store. Evidence sent to an AI provider is transmitted to that provider's API; do not submit sensitive or confidential material unless authorized.

## Current limitations

This is an initial functional foundation, not a mature enterprise platform. Username search, social platforms, threat feeds, graph visualization, advanced source validation, signed installers and AppImage packaging are planned modules.
