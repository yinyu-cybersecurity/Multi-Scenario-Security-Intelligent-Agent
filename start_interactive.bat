@echo off
chcp 65001 >nul
echo ============================================================
echo CTF-Agent Interactive Mode
echo ============================================================
echo.
echo Starting...
echo.

cd /d D:\LangGraph2.0\langGraph\deploy
venv312\Scripts\python -m app.interactive

pause