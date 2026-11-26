# Smart Toolbox — PyQt6 Desktop Edition

Native desktop GUI built with Python and PyQt6 for Windows, macOS and Linux. It contains 12 utilities: password generator, QR code generator, JSON formatter, Base64 converter, URL encoder/decoder, SHA-256, text toolkit, unit converter, UUID generator, color converter, timestamp converter and Markdown helper.

## Run from source

Requires Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate the environment:
- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Install and run:

```bash
python -m pip install -r requirements.txt
python main.py
```

## Build a standalone app

Build on the target OS; PyInstaller does not cross-compile.

- Windows: run `build_windows.bat` → `dist/SmartToolbox/SmartToolbox.exe`
- macOS: run `./build_macos.sh` → `dist/SmartToolbox.app`
- Linux: run `./build_linux.sh` → `dist/SmartToolbox/SmartToolbox`

See [BUILDING.md](BUILDING.md) for platform-specific instructions. macOS public distribution requires signing/notarization. Linux AppImage and OS-specific installers can be packaged as a follow-up release step.

All tool processing is local. No API keys or account are required.
