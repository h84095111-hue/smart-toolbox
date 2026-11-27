# Build Smart Intel

Use Python 3.10+ and build on the operating system you want to package for; PyInstaller is not a cross-compiler.

## Windows

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartIntel main.py
```

## macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartIntel main.py
```

Sign and notarize the app before distributing it publicly.

## Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --name SmartIntel main.py
```

For broad Linux compatibility, build on the oldest supported distribution. AppImage can be added as a separate packaging stage.
