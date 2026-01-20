@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%\.."

docker compose down

echo.
echo App stopped.
pause
