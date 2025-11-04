@echo off
setlocal ENABLEDELAYEDEXPANSION
set ROOT_DIR=%~dp0..
set PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%
set CONFIG_PATH=%1
if "%CONFIG_PATH%"=="" set CONFIG_PATH=%ROOT_DIR%\tests\node_configs\worker_orchestrated.json
if not "%1"=="" shift
python -m core_engine.worker_node --config "%CONFIG_PATH%" %*
endlocal
