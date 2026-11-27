# Smart Intel — AI OSINT Workstation

**A cross-platform, AI-assisted OSINT desktop app built with Python + PyQt6.** Collect public information, organize investigations, analyze evidence with your preferred AI provider and export source-linked reports.

> This repository is being redesigned from the earlier Smart Toolbox project into Smart Intel. The current desktop foundation is in [desktop/](desktop/).

## Desktop GUI

![Smart Intel desktop interface preview](desktop/assets/smart-intel-preview.svg)

*Concept preview of the Smart Intel investigation workspace; illustrative artwork, not a screenshot of the running application.*

## Current capabilities

- Investigation cases stored locally in SQLite.
- Passive domain lookups: DNS, RDAP registration and TLS certificate metadata.
- Public IP lookups: RDAP registration and reverse DNS; non-global addresses are rejected.
- Public website metadata: page title, description, selected security headers, links and bounded text excerpt.
- Optional OpenAI, Gemini and Claude analysis using user-supplied API keys.
- Local evidence timeline with timestamps, source URLs and confidence labels.
- HTML report export.

## Quick start

```bash
git clone https://github.com/h84095111-hue/smart-toolbox.git
cd smart-toolbox/desktop
python -m venv .venv
# Activate: Windows .venv\\Scripts\\Activate.ps1 | macOS/Linux source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Python 3.10+ is recommended. Configure AI keys in **AI provider settings**. Provider usage is billed separately.

## Build for your OS

- Windows: `desktop/build_windows.bat`
- macOS: `desktop/build_macos.sh`
- Linux: `desktop/build_linux.sh`

See [desktop/BUILDING.md](desktop/BUILDING.md). Build separately on each target OS; PyInstaller does not cross-compile. GitHub Actions builds on all three OS runners.

## Roadmap

1. More passive OSINT collectors (certificate transparency, DNS history providers, public threat feeds and company/news sources).
2. Entity relationship graph and investigation timeline visualization.
3. Multi-model compare mode and evidence-grounded agent workflows.
4. Additional export formats and portable installers (Windows installer, signed macOS app, Linux AppImage).
5. Automated tests, source validation and reproducible release builds.

## Responsible use and limitations

Smart Intel is intended for lawful, authorized research of public information. It does not bypass logins, exploit systems, scan ports, enumerate private accounts or access non-public data. Public data can be inaccurate or misleading; validate findings independently. Follow local law, provider terms, site policies and rate limits. AI outputs are hypotheses, not verified facts.

Cases are stored locally under `~/.smart-intel/data/`. API keys use the operating system credential store via `keyring`. When you submit evidence to an AI provider, that evidence is transmitted to that provider's API; do not submit confidential data without authorization.

## License

MIT — see [LICENSE](LICENSE).
