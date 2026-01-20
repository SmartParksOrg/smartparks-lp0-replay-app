@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%\.."

docker compose up -d --build
start "" "http://localhost:18080"

echo.
echo App is starting. If the browser did not open, visit http://localhost:18080
pause
