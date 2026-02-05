@echo off
title SecureLink Server
echo.
echo  ========================================
echo   Starting SecureLink Web Server...
echo  ========================================
echo.
echo  Once started, open your browser to:
echo.
echo    Main Site:    http://localhost:5000
echo    Admin Login:  http://localhost:5000/admin/login
echo    Database:     http://localhost:5000/admin/database
echo.
echo  Press Ctrl+C to stop the server.
echo  ========================================
echo.
cd /d "%~dp0"
.\.venv\Scripts\python.exe app.py
pause
