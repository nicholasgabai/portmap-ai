#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_DIR="${ROOT_DIR}/portmap-ai-env"
PYTHON_BIN="${PYTHON:-python3}"
if [ ! -d "${ENV_DIR}" ]; then
  echo "[+] Creating virtual environment at ${ENV_DIR}"
  "${PYTHON_BIN}" -m venv "${ENV_DIR}"
fi
source "${ENV_DIR}/bin/activate"
if [ -f "${ROOT_DIR}/requirements.txt" ]; then
  pip install -r "${ROOT_DIR}/requirements.txt"
fi
pip install -r "${ROOT_DIR}/requirements-dev.txt"
echo "[+] Environment ready. Activate via: source ${ENV_DIR}/bin/activate"
