#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --name SmartIntel main.py
echo 'Built in dist/SmartIntel'
