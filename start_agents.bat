@echo off
title SecureLink Agent Scheduler
echo Starting SecureLink Agent Scheduler...
echo Logs: agents\workspace\scheduler.log
echo Press Ctrl+C to stop.
echo.
cd /d "%~dp0"
.venv\Scripts\python.exe agents\run_scheduler.py
pause
