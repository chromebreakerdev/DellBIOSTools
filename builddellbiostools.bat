@echo off
setlocal EnableExtensions

rem =============================================================================
rem  DellBiosTools - Build EXE (local, flat output, PFS-safe)
rem =============================================================================

rem --- Safety: don't run from System32 ---
if /I "%CD%"=="C:\Windows\System32" (
    echo [!] Don't run from C:\Windows\System32.
    echo     Open the DellBIOSTools folder in Explorer, type CMD in the address bar,
    echo     and run this script again.
    pause
    exit /b 1
)

set ENTRY=DellBiosTools.pyw
set BUILDTMP=build_tmp

rem --- Ensure PyInstaller is available (UNCHANGED BEHAVIOR) ---
echo [*] Ensuring PyInstaller is available...
python -m pip install --upgrade pip pyinstaller
if errorlevel 1 (
    echo [!] pip/pyinstaller step failed.
    pause
    exit /b 1
)

rem --- Clean temp build folder ---
if exist "%BUILDTMP%" rmdir /s /q "%BUILDTMP%"

echo.
echo [*] Building EXE...
echo.

python -m PyInstaller ^
  --onefile ^
  --windowed ^
  --clean ^
  --noconfirm ^
  --distpath . ^
  --workpath "%BUILDTMP%" ^
  --specpath "%BUILDTMP%" ^
  --paths "%CD%\vendor" ^
  --hidden-import=PIL ^
  --hidden-import=PIL.Image ^
  --hidden-import=PIL.ImageTk ^
  --icon "%CD%\icon\DellBiosTools.ico" ^
  "%ENTRY%"

if errorlevel 1 (
    echo [!] PyInstaller failed.
    pause
    exit /b 1
)

rem --- Cleanup temp build folder ---
if exist "%BUILDTMP%" rmdir /s /q "%BUILDTMP%"

echo.
echo =========================================
echo   Build complete
echo   Output: DellBiosTools.exe (project root)
echo =========================================
echo.
pause
endlocal
exit /b 0
