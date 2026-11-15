@echo off
setlocal
set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"

set "CACHE_ROOT=D:\VPN\psiroute-go-2.0.3\.cache"
if not exist "%CACHE_ROOT%" set "CACHE_ROOT=%ROOT_DIR%\.cache"

set "GOCACHE=%CACHE_ROOT%\go-build"
set "GOMODCACHE=%CACHE_ROOT%\go-mod"
set "GOTMPDIR=%CACHE_ROOT%\tmp"
set "TEMP=%CACHE_ROOT%\tmp"
set "TMP=%CACHE_ROOT%\tmp"
set "GOPATH=%CACHE_ROOT%\gopath"
set "GOTOOLCHAIN=auto"

if not exist "%GOCACHE%" mkdir "%GOCACHE%"
if not exist "%GOMODCACHE%" mkdir "%GOMODCACHE%"
if not exist "%GOTMPDIR%" mkdir "%GOTMPDIR%"
if not exist "%GOPATH%" mkdir "%GOPATH%"
if not exist "%ROOT_DIR%\data\tmp" mkdir "%ROOT_DIR%\data\tmp"
if not exist "%ROOT_DIR%\data\reports" mkdir "%ROOT_DIR%\data\reports"

echo [PsiRoute] Building psiroute.exe (caches isolated in %CACHE_ROOT%)...
go build -trimpath -buildvcs=false -ldflags="-H=windowsgui -s -w" -o "%ROOT_DIR%\psiroute.exe" "%ROOT_DIR%"
if errorlevel 1 (
    echo [FAIL] Build failed!
    exit /b 1
)
echo [OK] Successfully built: %ROOT_DIR%\psiroute.exe
