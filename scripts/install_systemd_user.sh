#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${1:-portmap-ai-stack.service}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${PROJECT_ROOT}/deploy/systemd/${SERVICE_NAME}"
TARGET_DIR="${HOME}/.config/systemd/user"
TARGET="${TARGET_DIR}/${SERVICE_NAME}"
ENV_FILE="${HOME}/.portmap-ai/portmap-ai.env"

if [[ ! -f "${SOURCE}" ]]; then
  echo "Unknown systemd service template: ${SERVICE_NAME}" >&2
  echo "Available templates:" >&2
  ls "${PROJECT_ROOT}/deploy/systemd" >&2
  exit 1
fi

mkdir -p "${TARGET_DIR}"
cp "${SOURCE}" "${TARGET}"

mkdir -p "$(dirname "${ENV_FILE}")"
if [[ ! -f "${ENV_FILE}" ]]; then
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  {
    echo "PORTMAP_ORCHESTRATOR_TOKEN=${TOKEN}"
    echo "PORTMAP_ORCHESTRATOR_URL=http://127.0.0.1:9100"
  } > "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
fi

systemctl --user daemon-reload
systemctl --user enable "${SERVICE_NAME}"

echo "Installed ${SERVICE_NAME} to ${TARGET}"
echo "Environment file: ${ENV_FILE}"
echo "Start it with: systemctl --user start ${SERVICE_NAME}"
echo "Check status with: systemctl --user status ${SERVICE_NAME}"
