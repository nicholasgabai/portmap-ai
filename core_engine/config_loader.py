# core_engine/config_loader.py

"""
Utility helpers for loading PortMap-AI configuration and ensuring runtime
directories exist. Centralizes resolution of node configs (CLI/json files)
and shared ~/.portmap-ai settings used by the AI/agent layers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = Path.home() / ".portmap-ai"
DATA_DIR = APP_ROOT / "data"
LOG_DIR = APP_ROOT / "logs"
DEFAULT_SETTINGS_FILE = DATA_DIR / "settings.json"


def ensure_runtime_dirs() -> None:
    """Ensure ~/.portmap-ai data/log directories exist."""
    for path in (DATA_DIR, LOG_DIR):
        path.mkdir(parents=True, exist_ok=True)


ensure_runtime_dirs()


def _resolve_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    return candidate


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r") as handle:
        return json.load(handle)


def load_settings(defaults: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Load shared settings from ~/.portmap-ai/data/settings.json.
    Returns defaults merged with file contents when available.
    """
    config = defaults.copy() if defaults else {}
    if DEFAULT_SETTINGS_FILE.exists():
        try:
            config.update(_load_json(DEFAULT_SETTINGS_FILE))
        except Exception as exc:
            print(f"⚠️ Failed to read settings.json: {exc}")
    return config


def load_node_config(
    config_path: str | None,
    defaults: Dict[str, Any] | None = None,
    include_settings: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Load a node configuration JSON from the provided path.
    Returns a tuple of (node_config, global_settings).
    """
    config: Dict[str, Any] = {}
    if defaults:
        config.update(defaults)

    if config_path:
        resolved = _resolve_path(config_path)
        try:
            config.update(_load_json(resolved))
        except Exception as exc:
            raise RuntimeError(f"Failed to load node config '{config_path}': {exc}") from exc

    settings: Dict[str, Any] = {}
    if include_settings:
        settings = load_settings(
            defaults={
                "enable_autolearn": False,
                "remediation_mode": "prompt",  # prompt vs silent
                "remediation_threshold": 0.75,
                "orchestrator_token": "portmap-dev-token",
                "orchestrator_url": "http://127.0.0.1:9100",
                "log_max_bytes": 5 * 1024 * 1024,
                "log_backup_count": 5,
            }
        )

    return config, settings


__all__ = [
    "APP_ROOT",
    "DATA_DIR",
    "LOG_DIR",
    "load_settings",
    "load_node_config",
    "ensure_runtime_dirs",
]
