# Smart Intel installation

Smart Intel is a native Python/PyQt6 desktop application. The old Node/Vite browser-toolbox instructions no longer apply.

## Requirements

- Python 3.10 or newer
- Windows 10/11, recent macOS, or a supported Linux desktop
- Internet access for public-source lookups and AI APIs
- API keys only for the optional paid/provider integrations you choose

## Run from source

```bash
git clone https://github.com/h84095111-hue/smart-toolbox.git
cd smart-toolbox/desktop
python -m venv .venv
```

Activate the environment:

- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Then:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

The app creates its local data directory at `~/.smart-intel/data/`.

## API keys

Open **AI provider settings** inside the app. AI keys and supported OSINT provider keys are stored using the operating-system credential store via keyring. Some providers require an account, paid plan or specific API entitlement. Do not paste keys into source files or commit them to Git.

Supported source connectors include crt.sh, Wayback CDX and GDELT without a key, and VirusTotal, AbuseIPDB, OTX, Shodan, Censys, SecurityTrails and MISP with configured credentials. See [SOURCES.md](osint/SOURCES.md).

## Run tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Build locally

Use the scripts in `desktop/` and build on the target OS. See [desktop/BUILDING.md](../desktop/BUILDING.md). PyInstaller is not a cross-compiler. macOS signing/notarization and a Windows installer are not yet included.

## Troubleshooting

- If keyring is unavailable in a headless Linux session, configure a supported desktop secret service or use provider environment variables where supported.
- If a provider returns 401/403, check the API key, account plan, endpoint version and provider quota.
- Network lookups can fail due to provider rate limits, DNS, TLS inspection or regional restrictions.
- Do not disable TLS verification to work around certificate errors.
