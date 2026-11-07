@echo off
rem OpenScore launcher for Windows. Usage: openscore.bat example.com [options]
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 -m openscore %*
) else (
    python -m openscore %*
)
exit /b %ERRORLEVEL%
