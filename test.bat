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

echo [PsiRoute] Running go vet ./...
go vet ./...
if errorlevel 1 (
    echo [FAIL] go vet failed
    exit /b 1
)

echo [PsiRoute] Running go test ./...
go test ./...
if errorlevel 1 (
    echo [FAIL] go test failed
    exit /b 1
)

echo [OK] All checks and tests passed successfully!
