@echo off
title DellBIOSTools - Build EXE
echo =========================================
echo   DellBIOSTools EXE Builder (Hybrid)
echo =========================================
echo.

REM Force working directory to this BAT's location
pushd "%~dp0"

REM Repo paths
set PYTHON_REAL=%LOCALAPPDATA%\Programs\Python\Python311\python.exe
set PYTHON_INSTALLER=%CD%\python-3.11.9-amd64.exe
set SCRIPT=%CD%\DellBiosTools.pyw
set ICON_ICO=%CD%\icon\DellBiosTools.ico
set ICON_PNG=%CD%\icon\*.png

REM Check for real Python
if exist "%PYTHON_REAL%" goto PYTHON_OK

REM Try winget first (no MS Store source)
where winget >nul 2>nul
if %ERRORLEVEL%==0 (
    echo Installing Python via winget...
    winget install -e --id Python.Python.3.11 --source winget --accept-source-agreements --accept-package-agreements
    if exist "%PYTHON_REAL%" goto PYTHON_OK
    echo winget failed, falling back to bundled installer
)

REM Bundled installer fallback
echo Installing Python from bundled installer, please wait...
if not exist "%PYTHON_INSTALLER%" (
    echo ERROR: Bundled Python installer not found
    pause
    popd
    exit /b 1
)

"%PYTHON_INSTALLER%" /passive InstallAllUsers=0 PrependPath=0 Include_pip=1
timeout /t 5 >nul

if not exist "%PYTHON_REAL%" (
    echo ERROR: Python installation failed
    pause
    popd
    exit /b 1
)

:PYTHON_OK
echo Using Python:
echo %PYTHON_REAL%
echo.

REM Install dependencies
"%PYTHON_REAL%" -m ensurepip --upgrade
"%PYTHON_REAL%" -m pip install --upgrade pip
"%PYTHON_REAL%" -m pip install pillow pyinstaller

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python dependency installation failed
    pause
    popd
    exit /b 1
)

REM Build EXE into repo root
echo Building DellBIOSTools.exe...
"%PYTHON_REAL%" -m PyInstaller --onefile --noconsole --clean --distpath "%CD%" --workpath "%TEMP%\pyi_work" --specpath "%TEMP%\pyi_spec" --icon "%ICON_ICO%" --add-data "%ICON_PNG%;icon" --name DellBIOSTools "%SCRIPT%"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: PyInstaller build failed
    pause
    popd
    exit /b 1
)

REM Cleanup
rmdir /s /q "%TEMP%\pyi_work" >nul 2>nul
rmdir /s /q "%TEMP%\pyi_spec" >nul 2>nul
del /q "%CD%\DellBIOSTools.spec" >nul 2>nul

echo.
echo Build complete
echo DellBIOSTools.exe created in repo root
echo.

pause
popd
