@echo off
:: Run this on a Windows machine with Python 3.10+ installed.
:: Produces dist\Otzaria-USB-Lock.exe - a single file, admin-elevating
:: automatically thanks to --uac-admin, nothing else needed on the USB stick.

py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt

py -3 -m PyInstaller ^
  --onefile ^
  --windowed ^
  --uac-admin ^
  --name "Otzaria-USB-Lock" ^
  --icon "otzaria-usb-lock.ico" ^
  --add-data "logo-80.png;." ^
  --add-data "otzaria-usb-lock.ico;." ^
  otzaria_usb_lock.py

echo.
echo Done. Find the exe in the dist\ folder.
pause
