@echo off
set SCRIPT_DIR=%~dp0
set REPO_ROOT=%SCRIPT_DIR%..
py -3 "%REPO_ROOT%\src\rtdx_save_codec.py" %*
if errorlevel 1 pause
