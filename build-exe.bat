@echo off
REM Build the GUI as a Windows EXE with PyInstaller (English-only).
REM Usage: double-click build-exe.bat, output goes to dist\SSLCertGen.exe
setlocal

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python not found in PATH.
  pause
  exit /b 1
)

echo [1/3] Installing dependencies...
python -m pip install --upgrade pip
if errorlevel 1 goto :fail
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto :fail

echo [2/3] Building GUI EXE (windowed, onefile)...
python -m PyInstaller --clean --noconfirm --onefile --windowed --name SSLCertGen --collect-all cryptography cert_gui.py
if errorlevel 1 goto :fail

echo [3/3] Done. Output in dist\ folder:
dir dist\*.exe
start "" "dist"
pause
exit /b 0

:fail
echo [ERROR] Build failed with code %errorlevel%.
pause
exit /b 1
