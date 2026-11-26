# Cross-platform packaging guide

Build each desktop target on its own operating system and architecture. PyInstaller is not a cross-compiler.

## Windows

Install Python 3.10+, open a terminal in `desktop/`, then run:

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartToolbox --collect-all qrcode main.py
```

Output: `dist/SmartToolbox/SmartToolbox.exe`.

## macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartToolbox --collect-all qrcode main.py
```

Output: `dist/SmartToolbox.app`. Sign and notarize before public distribution so Gatekeeper can verify it.

## Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --name SmartToolbox --collect-all qrcode main.py
```

Output: `dist/SmartToolbox/SmartToolbox`. Build on the oldest Linux distribution you intend to support where practical. AppImage packaging can be added for a more portable Linux download.

## Release checklist

- Test the app on a clean machine for each OS.
- Verify QR generation, save, clipboard, and converter operations.
- Sign/notarize macOS builds; consider signing Windows executables.
- Add OS-specific installers/AppImage if desired.
