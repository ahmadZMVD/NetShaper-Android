@echo off
setlocal
cd /d "%~dp0"
set CGO_ENABLED=0
set REPORT=mobilecore_test_report.txt

echo NetShaper Mobilecore Phase-2 Verification Report > "%REPORT%"
echo ================================================= >> "%REPORT%"

echo.
echo === [1/4] Resolving Go dependencies (go mod tidy) ===
echo === [1/4] go mod tidy === >> "%REPORT%"
go mod tidy >> "%REPORT%" 2>&1
if errorlevel 1 goto :fail

echo === [2/4] Running static parity and gomobile ABI audit ===
echo === [2/4] verify_mobile_parity.py === >> "%REPORT%"
python verify_mobile_parity.py >> "%REPORT%" 2>&1
if errorlevel 1 goto :fail

echo === [3/4] Running go vet ./... ===
echo === [3/4] go vet ./... === >> "%REPORT%"
go vet ./... >> "%REPORT%" 2>&1
if errorlevel 1 goto :fail

echo === [4/4] Running MT-01..MT-15 unit and chaos test suite ===
echo === [4/4] go test -v -count=1 ./... === >> "%REPORT%"
go test -v -count=1 ./... >> "%REPORT%" 2>&1
if errorlevel 1 goto :fail

echo.
echo =================================================
echo   ALL 15 MOBILECORE TESTS PASSED!
echo   Report saved to: mobilecore_test_report.txt
echo =================================================
type "%REPORT%"
echo.
pause
exit /b 0

:fail
echo.
echo =================================================
echo   TEST FAILED! Full output below (also saved to %REPORT%):
echo =================================================
type "%REPORT%"
echo.
pause
exit /b 1
