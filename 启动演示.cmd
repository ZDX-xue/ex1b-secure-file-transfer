@echo off
setlocal
cd /d "%~dp0"
set "ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
set "EX1B=bin\ex1b-windows-%ARCH%.exe"
if not exist "%EX1B%" (
  where go >nul 2>nul || (
    echo EX1B binary missing. To build from source, install Go 1.25 or newer.
    pause
    exit /b 1
  )
  if not exist bin mkdir bin
  go build -trimpath -o "%EX1B%" ./cmd/ex1b || exit /b 1
)
if not exist demo\server.json "%EX1B%" init --dir demo
if errorlevel 1 exit /b 1
start "EX1B Server" "%EX1B%" server --config demo/server.json
start "EX1B Alice" "%EX1B%" client --config demo/alice.json
start "EX1B VIP" "%EX1B%" client --config demo/vip.json
timeout /t 2 /nobreak >nul
start "" http://127.0.0.1:43950
start "" http://127.0.0.1:43952
start "" http://127.0.0.1:43953
