@echo off
set ROOT_DIR=%~dp0..
set ENV_DIR=%ROOT_DIR%\portmap-ai-env
if not exist "%ENV_DIR%" (
  echo [+] Creating virtual environment at %ENV_DIR%
  python -m venv "%ENV_DIR%"
)
call "%ENV_DIR%\Scripts\activate.bat"
if exist "%ROOT_DIR%\requirements.txt" (
  pip install -r "%ROOT_DIR%\requirements.txt"
)
pip install -r "%ROOT_DIR%\requirements-dev.txt"
echo [+] Environment ready. Activate via: call %ENV_DIR%\Scripts\activate.bat
