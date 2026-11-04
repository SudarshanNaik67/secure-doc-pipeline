@echo off
setlocal
cd /d "%~dp0"
set "DOCKER=%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"
if not exist "%DOCKER%" set "DOCKER=C:\Program Files\Docker\Docker\resources\bin\docker.exe"
"%DOCKER%" compose down
echo.
echo Stopped.
pause
