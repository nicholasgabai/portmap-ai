# core_engine/config_loader.py

"""
Utility helpers for loading PortMap-AI configuration and ensuring runtime
directories exist. Centralizes resolution of node configs (CLI/json files)
and shared ~/.portmap-ai settings used by the AI/agent layers.
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"
PROFILE_DIR = CONFIG_DIR / "profiles"
APP_ROOT = Path.home() / ".portmap-ai"
DATA_DIR = APP_ROOT / "data"
LOG_DIR = APP_ROOT / "logs"
DEFAULT_SETTINGS_FILE = DATA_DIR / "settings.json"
ENV_PATTERN = re.compile(r"\$\{([^:}]+)(?::([^}]*))?\}")


def get_default_orchestrator_url() -> str:
    return os.environ.get("PORTMAP_ORCHESTRATOR_URL", "http://127.0.0.1:9100")


def get_default_orchestrator_token() -> str:
    return os.environ.get("PORTMAP_ORCHESTRATOR_TOKEN", "test-token")


def get_default_export_dir() -> str:
    return os.environ.get("PORTMAP_EXPORT_DIR", str(Path.home() / "Downloads" / "portmap-ai-exports"))


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


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = deepcopy(base)
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and isinstance(result.get(key), dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _resolve_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            var = match.group(1)
            default = match.group(2) or ""
            if var == "secret":
                return os.environ.get(default, "")
            return os.environ.get(var, default)

        return ENV_PATTERN.sub(repl, value)
    return value


def _load_profile(profile_name: str) -> Dict[str, Any]:
    profile_path = PROFILE_DIR / f"{profile_name}.json"
    if not profile_path.exists():
        print(f"⚠️ Profile '{profile_name}' not found at {profile_path}")
        return {}
    return _resolve_env(_load_json(profile_path))


def load_settings(defaults: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Load shared settings from ~/.portmap-ai/data/settings.json.
    Returns defaults merged with file contents when available.
    """
    config = deepcopy(defaults) if defaults else {}
    if DEFAULT_SETTINGS_FILE.exists():
        try:
            config = _deep_merge(config, _resolve_env(_load_json(DEFAULT_SETTINGS_FILE)))
        except Exception as exc:
            print(f"⚠️ Failed to read settings.json: {exc}")
    return config


def save_settings(settings: Dict[str, Any]) -> None:
    """Persist shared runtime settings to ~/.portmap-ai/data/settings.json."""
    ensure_runtime_dirs()
    DEFAULT_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_SETTINGS_FILE, "w") as handle:
        json.dump(settings, handle, indent=2, sort_keys=True)
        handle.write("\n")


def load_node_config(
    config_path: str | None,
    defaults: Dict[str, Any] | None = None,
    include_settings: bool = True,
    profile: str | None = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Load a node configuration JSON from the provided path.
    Returns a tuple of (node_config, global_settings).
    """
    config: Dict[str, Any] = deepcopy(defaults) if defaults else {}

    profile_name = profile or (defaults.get("profile") if defaults else None)
    profile_config: Dict[str, Any] = {}

    file_data: Dict[str, Any] = {}
    resolved_path: Path | None = None

    if config_path:
        resolved = _resolve_path(config_path)
        try:
            file_data = _load_json(resolved)
            resolved_path = resolved
        except Exception as exc:
            raise RuntimeError(f"Failed to load node config '{config_path}': {exc}") from exc

    if file_data:
        profile_name = file_data.get("profile", profile_name)

    if profile_name:
        profile_config = _load_profile(profile_name)
        config = _deep_merge(config, profile_config)

    if file_data:
        config = _deep_merge(config, _resolve_env(file_data))

    if profile_name and "profile" not in config:
        config["profile"] = profile_name

    settings: Dict[str, Any] = {}
    if include_settings:
        settings = load_settings(
            defaults={
                "enable_autolearn": False,
                "remediation_mode": "prompt",  # prompt vs silent
                "remediation_threshold": 0.75,
                "orchestrator_token": get_default_orchestrator_token(),
                "orchestrator_url": get_default_orchestrator_url(),
                "export_dir": get_default_export_dir(),
                "expected_services": [],
                "log_max_bytes": 5 * 1024 * 1024,
                "log_backup_count": 5,
                "tls": {
                    "enabled": False,
                    "verify": True,
                    "require_client_auth": False,
                },
            }
        )

    config = _resolve_env(config)
    return config, settings


__all__ = [
    "APP_ROOT",
    "DATA_DIR",
    "LOG_DIR",
    "CONFIG_DIR",
    "PROFILE_DIR",
    "load_settings",
    "save_settings",
    "load_node_config",
    "ensure_runtime_dirs",
]
