@echo off
setlocal
cd /d "%~dp0"
set "EX1B=bin\ex1b-web-windows-amd64.exe"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "EX1B=bin\ex1b-web-windows-arm64.exe"
if not exist "%EX1B%" (
  where go >nul 2>nul || (
    echo EX1B binary missing. To build, install Go 1.25 or newer.
    pause
    exit /b 1
  )
  if not exist bin mkdir bin
  go build -trimpath -o "%EX1B%" ./cmd/ex1b || exit /b 1
)
start "EX1B Web" "%EX1B%" web --listen 127.0.0.1:44080 --origin http://127.0.0.1:44080 --admin-port 44081 --user-ports 44082,44083,44084 --data web-data
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:44080
