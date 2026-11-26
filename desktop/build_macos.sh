#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartToolbox --collect-all qrcode main.py
echo 'Built: dist/SmartToolbox.app'
