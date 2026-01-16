@echo off
setlocal EnableExtensions

rem =============================================================================
rem  DellBiosTools - Build EXE (flat output, EXE-safe, Pillow bundled)
rem =============================================================================

rem --- Anchor to script directory (CRITICAL) ---
cd /d "%~dp0"

rem --- Safety: don't run from System32 ---
if /I "%CD%"=="C:\Windows\System32" (
    echo [!] Don't run from C:\Windows\System32.
    pause
    exit /b 1
)

set ENTRY=DellBiosTools.pyw
set BUILDTMP=build_tmp

echo.
echo [*] Ensuring PyInstaller + Pillow are available...
python -m pip install --upgrade pip pyinstaller pillow
if errorlevel 1 (
    echo [!] pip / pyinstaller / pillow step failed.
    pause
    exit /b 1
)

rem --- Resolve icon dynamically ---
set ICON_ARG=
set ICON_DIR=%CD%\icon

for %%I in (
    DellBiosTools.ico
    DellBiostools.ico
    DellBIOSTools.ico
    dellbiostools.ico
) do (
    if exist "%ICON_DIR%\%%I" (
        set "ICON_ARG=--icon=%ICON_DIR%\%%I"
        echo {ok} Icon will be embedded : %ICON_DIR%\%%I
        goto :ICON_FOUND
    )
)

echo {warn} No icon found in %ICON_DIR%
:ICON_FOUND

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
  --collect-all PIL ^
  --add-data "%CD%\icon;icon" ^
  %ICON_ARG% ^
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
echo   Output: DellBiosTools.exe
echo =========================================
echo.
pause
endlocal
exit /b 0
