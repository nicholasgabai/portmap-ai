#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
ARCHIVE_NAME="portmap-ai-$(date +%Y%m%d-%H%M%S).tar.gz"
mkdir -p "${DIST_DIR}"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "${TMP_DIR}"; }
trap cleanup EXIT
rsync -a --exclude '.git' --exclude 'dist' --exclude '__pycache__' --exclude '.pytest_cache' \
  --exclude '*.pyc' --exclude '*.pyo' \
  "${ROOT_DIR}/" "${TMP_DIR}/portmap-ai/"
cat <<'README' > "${TMP_DIR}/portmap-ai/INSTALL.md"
# PortMap-AI Local Bundle

1. Create/activate a Python 3.11 virtual environment.
2. `pip install -r requirements.txt`
3. `pip install -e .`
4. `portmap setup`
5. `portmap doctor`
6. Use `portmap stack` or `scripts/run_stack.py` to launch orchestrator, master, worker, and dashboard.

Certificates can be generated via `scripts/generate_certs.py` if TLS is enabled.

Docker is optional. Raspberry Pi is supported through the Linux/ARM local install and systemd guidance; it is not a separate product path.
README
pushd "${TMP_DIR}" >/dev/null
 tar -czf "${DIST_DIR}/${ARCHIVE_NAME}" portmap-ai
popd >/dev/null
printf "Created archive: %s\n" "${DIST_DIR}/${ARCHIVE_NAME}"
