@echo off
echo ============================================
echo CTF-Agent Web UI
echo ============================================
echo.

cd /d %~dp0

echo Starting web server...
echo Access URL: http://localhost:5000
echo.

python web\api.py

pause