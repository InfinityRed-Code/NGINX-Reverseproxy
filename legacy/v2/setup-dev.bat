@echo off
echo ========================================
echo NRP Development Setup (Windows)
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python ist nicht installiert oder nicht im PATH!
    echo Bitte installieren Sie Python 3.8 oder neuer.
    pause
    exit /b 1
)

echo Python gefunden:
python --version
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Erstelle Virtual Environment...
    python -m venv venv
    echo Virtual Environment erstellt.
) else (
    echo Virtual Environment existiert bereits.
)
echo.

REM Activate virtual environment and install dependencies
echo Aktiviere Virtual Environment und installiere Dependencies...
call venv\Scripts\activate.bat

echo Installiere Dependencies...
pip install --upgrade pip
pip install -e .

echo.
echo ========================================
echo Setup abgeschlossen!
echo ========================================
echo.
echo Zum Aktivieren der Virtual Environment:
echo   venv\Scripts\activate
echo.
echo Zum Testen der Installation:
echo   nrp --help
echo.
pause
