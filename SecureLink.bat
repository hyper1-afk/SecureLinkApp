@echo off
title SecureLink Launcher
cd /d "%~dp0"

:menu
cls
echo.
echo  ========================================
echo   SecureLink Control Center
echo  ========================================
echo.
echo   [SERVER]
echo   1. Start Web Server (Local Development)
echo.
echo   [ADMIN TOOLS]
echo   2. Open Admin Manager (Desktop App)
echo   3. Open Admin Page in Browser
echo   4. List Employees (Command Line)
echo.
echo   [DEPLOYMENT]
echo   5. Deploy to Production
echo   6. Check Deployment Status
echo   7. View Production Logs
echo.
echo   [EXIT]
echo   0. Exit
echo.
echo  ========================================
echo.

set /p choice="Enter choice (0-7): "

if "%choice%"=="1" (
    echo Starting local server...
    start "SecureLink Server" cmd /k ".\.venv\Scripts\python.exe app.py"
    timeout /t 3 >nul
    start http://localhost:5000/admin/login
    goto menu
)
if "%choice%"=="2" (
    echo Launching Admin Manager...
    start "" ".\.venv\Scripts\pythonw.exe" admin_manager_gui.py
    goto menu
)
if "%choice%"=="3" (
    start http://localhost:5000/admin/login
    goto menu
)
if "%choice%"=="4" (
    .\.venv\Scripts\python.exe manage_admins.py list
    pause
    goto menu
)
if "%choice%"=="5" (
    echo.
    echo Starting deployment wizard...
    echo.
    .\.venv\Scripts\python.exe deploy.py
    pause
    goto menu
)
if "%choice%"=="6" (
    .\.venv\Scripts\python.exe deploy.py --check
    pause
    goto menu
)
if "%choice%"=="7" (
    echo Press Ctrl+C to stop viewing logs...
    .\.venv\Scripts\python.exe deploy.py --logs
    goto menu
)
if "%choice%"=="0" goto end

echo Invalid choice.
timeout /t 2 >nul
goto menu

:end
