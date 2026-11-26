@echo off
python -m pip install -r requirements-dev.txt
pyinstaller --noconfirm --clean --windowed --name SmartToolbox --collect-all qrcode main.py
echo Built: dist\SmartToolbox\SmartToolbox.exe
