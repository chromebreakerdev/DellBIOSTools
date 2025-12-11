@echo off
setlocal EnableExtensions

rem =============================================================================
rem  DellBiosTools - Build EXE (local)
rem =============================================================================

rem --- Safety: don't run from System32 ---
if /I "%CD%"=="C:\Windows\System32" (
    echo [!] Don't run from C:\Windows\System32.
    echo     Open the DellBIOSTools folder in Explorer, type CMD in the address bar,
    echo     and run this script again.
    pause
    exit /b 1
)

rem --- Safety: don't run as Administrator ---
net session >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [!] You're running this as Administrator.
    echo     Close this window and run as a normal user.
    pause
    exit /b 1
)

echo =====================================
echo   DellBiosTools - Build EXE (local)
echo =====================================
echo [i] Working dir: %CD%
echo.

rem --- Core settings -----------------------------------------------------------
set "APP_NAME=DellBiosTools"
set "ENTRY=DellBiosTools.pyw"

set "WORK=__pyi_tmp\build"
set "SPEC=__pyi_tmp\spec"

set "ICONDIR=%CD%\icon"
set "ICONFILE=%ICONDIR%\DellBiosTools.ico"

rem --- Check main script exists ------------------------------------------------
if not exist "%ENTRY%" (
    echo [!] %ENTRY% not found in this folder:
    echo     %CD%
    echo     Make sure this BAT lives next to %ENTRY%.
    pause
    exit /b 1
)

rem --- Icon handling -----------------------------------------------------------
set "HAVE_ICON=0"
if exist "%ICONFILE%" (
    set "HAVE_ICON=1"
    echo [OK] Icon will be embedded: %ICONFILE%
) else (
    echo [i] No icon found at: %ICONFILE%
)
echo.

rem --- Ensure PyInstaller is available ----------------------------------------
echo [*] Ensuring PyInstaller is available...
python -m pip install --upgrade pip pyinstaller
if errorlevel 1 (
    echo [!] pip/pyinstaller step failed.
    pause
    exit /b 1
)
echo.

rem --- Clean previous build artifacts -----------------------------------------
echo [*] Cleaning previous build artifacts...
rmdir /s /q "%WORK%" 2>nul
rmdir /s /q "%SPEC%" 2>nul
rmdir /s /q "build" 2>nul
rmdir /s /q "dist" 2>nul
del /q "%APP_NAME%.spec" 2>nul
echo.

rem --- Build -------------------------------------------------------------------
echo [*] Building...

if "%HAVE_ICON%"=="1" (
    rem Show exact command
    echo python -m PyInstaller -F -w --clean --noconfirm -n "%APP_NAME%" --distpath "." --workpath "%WORK%" --specpath "%SPEC%" --paths "%CD%\vendor" --icon "%ICONFILE%" "%ENTRY%"
    echo.
    python -m PyInstaller -F -w --clean --noconfirm ^
        -n "%APP_NAME%" ^
        --distpath "." ^
        --workpath "%WORK%" ^
        --specpath "%SPEC%" ^
        --paths "%CD%\vendor" ^
        --icon "%ICONFILE%" ^
        "%ENTRY%"
) else (
    rem No icon
    echo python -m PyInstaller -F -w --clean --noconfirm -n "%APP_NAME%" --distpath "." --workpath "%WORK%" --specpath "%SPEC%" --paths "%CD%\vendor" "%ENTRY%"
    echo.
    python -m PyInstaller -F -w --clean --noconfirm ^
        -n "%APP_NAME%" ^
        --distpath "." ^
        --workpath "%WORK%" ^
        --specpath "%SPEC%" ^
        --paths "%CD%\vendor" ^
        "%ENTRY%"
)

if errorlevel 1 (
    echo.
    echo [!] Build failed.
    pause
    exit /b 1
)

echo.
echo [OK] PyInstaller finished.

rem --- Final EXE check ---------------------------------------------------------
if exist "%APP_NAME%.exe" (
    echo [OK] Final EXE: %CD%\%APP_NAME%.exe
) else (
    if exist ".\dist\%APP_NAME%\%APP_NAME%.exe" (
        move /Y ".\dist\%APP_NAME%\%APP_NAME%.exe" ".\%APP_NAME%.exe" >nul 2>&1
    )
    if exist "%APP_NAME%.exe" (
        echo [OK] Final EXE moved to: %CD%\%APP_NAME%.exe
    ) else (
        echo [!] Build finished but EXE not found.
    )
)

rem --- Cleanup temp dirs -------------------------------------------------------
echo.
echo [*] Cleaning temp...
rmdir /s /q "%WORK%" 2>nul
rmdir /s /q "%SPEC%" 2>nul
rmdir /s /q "__pyi_tmp" 2>nul
echo.

echo Done.
echo.
pause
endlocal
exit /b 0
