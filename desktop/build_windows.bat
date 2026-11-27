@echo off
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartIntel main.py
echo Built in dist\SmartIntel\SmartIntel.exe
