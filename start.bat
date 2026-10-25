@echo off
setlocal EnableDelayedExpansion

:: ============================================================
::  SHADOWPATH Omega -- NEXUS  |  start.bat
::  Double-click to launch API, worker, and web UI.
::  Login: parth / parth
:: ============================================================

set PYTHON=C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe
if not exist "%PYTHON%" set PYTHON=python
set ROOT=%~dp0
set API_PORT=8000
set WEB_PORT=5174
set WEB_URL=http://127.0.0.1:%WEB_PORT%

title SHADOWPATH NEXUS -- Launcher

:: Kill stale processes on API port
echo [1/5] Checking port %API_PORT%...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%API_PORT% " ^| findstr "LISTENING"') do (
    echo       Killing stale PID %%P on port %API_PORT%
    taskkill /PID %%P /F >nul 2>&1
)

:: Kill any leftover named windows
echo [2/5] Clearing old python workers...
taskkill /F /FI "WINDOWTITLE eq SHADOWPATH API*"    >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq SHADOWPATH Worker*" >nul 2>&1
timeout /t 1 /nobreak >nul

:: Start API
echo [3/5] Starting API on port %API_PORT%...
start "SHADOWPATH API -- port %API_PORT%" /MIN cmd /c "cd /d "%ROOT%" && "%PYTHON%" -m uvicorn backend.api:app --host 127.0.0.1 --port %API_PORT%"

:: Start Worker
echo [4/5] Starting analysis worker...
start "SHADOWPATH Worker" /MIN cmd /c "cd /d "%ROOT%" && "%PYTHON%" -m backend.worker"

:: Wait for API ready (max 20 s)
echo       Waiting for API...
set /a TRIES=0
:WAIT_LOOP
timeout /t 1 /nobreak >nul
set /a TRIES+=1
curl -s -o nul -w "%%{http_code}" http://127.0.0.1:%API_PORT%/health 2>nul | findstr /C:"200" >nul 2>&1
if %ERRORLEVEL%==0 goto API_READY
if %TRIES% GEQ 20 (
    echo       WARNING: API did not respond in 20s -- check the API window.
    goto START_WEB
)
goto WAIT_LOOP

:API_READY
echo       API ready!

:: Start Vite dev server
:START_WEB
echo [5/5] Starting web UI on %WEB_URL%...
start "SHADOWPATH Web -- %WEB_URL%" /MIN cmd /c "cd /d "%ROOT%\frontend" && npm run dev -- --host 127.0.0.1 --port %WEB_PORT%"

:: Wait then open browser
timeout /t 4 /nobreak >nul
echo.
echo  ================================================
echo   SHADOWPATH NEXUS is starting up
echo   URL   : %WEB_URL%
echo   Login : parth / parth
echo  ================================================
echo.
start "" "%WEB_URL%"

echo  Three background windows are running (minimised).
echo  Press any key here to STOP all services and exit.
echo.
pause >nul

:: Cleanup on exit
echo Stopping services...
taskkill /F /FI "WINDOWTITLE eq SHADOWPATH API*"    >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq SHADOWPATH Worker*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq SHADOWPATH Web*"    >nul 2>&1
echo Done. Goodbye.
endlocal
