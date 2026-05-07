#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}:${PYTHONPATH:-}"
python -m pytest tests/test_config_loader.py tests/test_firewall_plugins.py tests/test_dispatcher.py --maxfail=1
