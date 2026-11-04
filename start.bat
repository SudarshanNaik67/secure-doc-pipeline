@echo off
setlocal
cd /d "%~dp0"

rem --- Locate docker.exe (per-user install first, then all-users install) ---
set "DOCKER=%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"
if not exist "%DOCKER%" set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
if not exist "%DOCKER%" (
  echo Could not find docker.exe. Is Docker Desktop installed?
  pause
  exit /b 1
)

echo Using: %DOCKER%
"%DOCKER%" --version
echo.
echo Building and starting the stack. The first run takes several minutes...
echo.
"%DOCKER%" compose up --build -d
if errorlevel 1 (
  echo.
  echo *** Something failed. Scroll up to read the error, then send it to me. ***
  pause
  exit /b 1
)

echo.
"%DOCKER%" compose ps
echo.
echo ================= DONE =================
echo Open this in your browser:  http://localhost:8000/docs
echo.
pause
