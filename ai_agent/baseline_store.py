from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any

from core_engine.config_loader import DATA_DIR, ensure_runtime_dirs


BASELINE_VERSION = 1
DEFAULT_BASELINE_FILE = DATA_DIR / "behavior_baseline.json"


def empty_baseline() -> dict[str, Any]:
    return {
        "version": BASELINE_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": None,
        "devices": {},
    }


def load_baseline(path: str | Path | None = None) -> dict[str, Any]:
    baseline_path = Path(path).expanduser() if path else DEFAULT_BASELINE_FILE
    if not baseline_path.exists():
        return empty_baseline()
    try:
        with open(baseline_path, "r") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return empty_baseline()
    return normalize_baseline(data)


def save_baseline(baseline: dict[str, Any], path: str | Path | None = None) -> Path:
    ensure_runtime_dirs()
    baseline_path = Path(path).expanduser() if path else DEFAULT_BASELINE_FILE
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = normalize_baseline(baseline)
    normalized["updated_at"] = datetime.now(UTC).isoformat()
    temp_path = baseline_path.with_suffix(f"{baseline_path.suffix}.tmp")
    with open(temp_path, "w") as handle:
        json.dump(normalized, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp_path.replace(baseline_path)
    return baseline_path


def normalize_baseline(baseline: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(baseline, dict):
        return empty_baseline()
    normalized = deepcopy(baseline)
    normalized["version"] = BASELINE_VERSION
    normalized.setdefault("created_at", datetime.now(UTC).isoformat())
    normalized.setdefault("updated_at", None)
    devices = normalized.get("devices")
    if not isinstance(devices, dict):
        devices = {}
    normalized["devices"] = {
        str(device_id): normalize_device_profile(profile)
        for device_id, profile in devices.items()
        if isinstance(profile, dict)
    }
    return normalized


def normalize_device_profile(profile: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = dict(profile or {})
    normalized = {
        "event_count": _int(profile.get("event_count")),
        "first_seen": profile.get("first_seen"),
        "last_seen": profile.get("last_seen"),
        "ports": _count_map(profile.get("ports")),
        "peers": _count_map(profile.get("peers")),
        "applications": _count_map(profile.get("applications")),
        "transports": _count_map(profile.get("transports")),
        "hour_buckets": _count_map(profile.get("hour_buckets")),
    }
    return normalized


def _count_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _int(count) for key, count in value.items() if _int(count) > 0}


def _int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0
