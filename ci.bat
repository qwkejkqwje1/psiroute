@echo off
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "CACHE=%ROOT%\.cache"
if not exist "%CACHE%\tmp" mkdir "%CACHE%\tmp"

if exist "C:\ProgramData\mingw64\mingw64\bin" set "PATH=C:\ProgramData\mingw64\mingw64\bin;%PATH%"
set "GO_BIN=go"
where go >nul 2>nul || (
    if exist "R:\разработка\12\.tools\go\bin\go.exe" set "GO_BIN=R:\разработка\12\.tools\go\bin\go.exe"
)

set "CGO_ENABLED=1"
if exist "C:\Users\1\go\pkg\mod" (
    set "GOMODCACHE=C:\Users\1\go\pkg\mod"
    set "MOD_FLAG=-mod=readonly"
) else (
    set "MOD_FLAG="
)
set "GOCACHE=%CACHE%\go-build"
set "GOTMPDIR=%CACHE%\tmp"
set "TMP=%CACHE%\tmp"
set "TEMP=%CACHE%\tmp"
set "GOPATH=%CACHE%\gopath"
set "GOENV=%CACHE%\goenv"
set "GOTELEMETRYDIR=%CACHE%\telemetry"
set "GOTOOLCHAIN=local"
set "GOTELEMETRY=off"

echo [1/3] Running go vet...
"%GO_BIN%" vet %MOD_FLAG% ./...
if errorlevel 1 exit /b %errorlevel%

echo [2/3] Running go test -race...
"%GO_BIN%" test -race %MOD_FLAG% -buildvcs=false -count=1 -timeout 240s ./...
if errorlevel 1 exit /b %errorlevel%

echo [3/3] Building psiroute.exe...
"%GO_BIN%" build %MOD_FLAG% -trimpath -buildvcs=false -ldflags="-H=windowsgui -s -w" -o "%ROOT%\psiroute.exe" .
if errorlevel 1 exit /b %errorlevel%

echo CI checks and build succeeded cleanly.
