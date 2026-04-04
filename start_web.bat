@echo off
chcp 65001 >nul
echo ============================================================
echo CTF-Agent Web Interface
echo ============================================================
echo.
echo Starting backend server on http://localhost:8000
echo.

cd /d D:\LangGraph2.0\langGraph\deploy
venv312\Scripts\python -m app.web_server

pause