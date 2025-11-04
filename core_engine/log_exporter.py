# core_engine/log_exporter.py

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional
from zipfile import ZIP_DEFLATED, ZipFile

from .config_loader import DATA_DIR, LOG_DIR, ensure_runtime_dirs


def _iter_paths(root: Path, patterns: Iterable[str]) -> Iterable[Path]:
    for pattern in patterns:
        yield from root.glob(pattern)


def export_logs(output_dir: Optional[str] = None, include_state: bool = True) -> Path:
    """
    Create a timestamped zip archive containing PortMap-AI logs (and optionally state files).

    Parameters
    ----------
    output_dir:
        Destination directory for the archive. Defaults to ``~/.portmap-ai/logs/exports``.
    include_state:
        When True, include relevant files from ``~/.portmap-ai/data`` for full audit trails.

    Returns
    -------
    Path
        Filesystem path to the created archive.
    """

    ensure_runtime_dirs()
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    dest_dir = Path(output_dir).expanduser() if output_dir else Path(LOG_DIR) / "exports"
    dest_dir.mkdir(parents=True, exist_ok=True)

    archive_path = dest_dir / f"portmap-logs-{timestamp}.zip"

    log_root = Path(LOG_DIR)
    data_root = Path(DATA_DIR)

    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
        for path in _iter_paths(log_root, ["*.log", "*.log.*", "*.jsonl", "events/**/*.jsonl"]):
            if path.is_file():
                archive.write(path, arcname=str(path.relative_to(log_root.parent)))

        if include_state and data_root.exists():
            for path in data_root.rglob("*.json"):
                if path.is_file():
                    archive.write(path, arcname=str(path.relative_to(log_root.parent)))

    return archive_path


__all__ = ["export_logs"]
