@echo off
setlocal ENABLEDELAYEDEXPANSION
set ROOT_DIR=%~dp0..
set PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%
python -m cli.dashboard %*
endlocal
