@echo off
echo Starting SmartConsent Guard Backend...
echo Server running at http://127.0.0.1:8000
cd /d "%~dp0backend"
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe main.py
) else (
    python main.py
)
pause
