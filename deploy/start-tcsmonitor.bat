@echo off
rem TCsMonitor startup script for Windows Task Scheduler.
rem Task Scheduler: Trigger "At startup", Action "Start a program" -> this file,
rem tick "Run whether user is logged on or not" and "Run with highest privileges"
rem (highest privileges = Administrator, needed for the packet log).

cd /d "%~dp0.."
set TCSM_PASSWORD=change-me
set TCSM_PORT=8000
set TCSM_INTERVAL=10
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port %TCSM_PORT% --workers 1 >> data\server.log 2>&1
