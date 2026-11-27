#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartIntel main.py
echo 'Built in dist/SmartIntel.app or dist/SmartIntel depending on PyInstaller output'
