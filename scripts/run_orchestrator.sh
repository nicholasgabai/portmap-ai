#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"
CONFIG_PATH="${1:-${ROOT_DIR}/tests/node_configs/orchestrator.json}"
shift || true
python -m core_engine.orchestrator --config "${CONFIG_PATH}" "$@"
