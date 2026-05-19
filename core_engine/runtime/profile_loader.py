from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core_engine.runtime.profiles import (
    RuntimeProfile,
    RuntimeProfileError,
    default_runtime_profile,
    edge_device_runtime_profile,
    merge_runtime_profiles,
    runtime_profile_from_dict,
    runtime_profile_to_dict,
    summarize_runtime_profile,
    validate_runtime_profile,
)


BUILT_IN_PROFILE_NAMES = frozenset({"default", "edge-device", "raspberry-pi"})


def get_builtin_runtime_profile(name: str = "default") -> RuntimeProfile:
    normalized = str(name or "default").strip().lower()
    if normalized == "default":
        return default_runtime_profile()
    if normalized in {"edge-device", "raspberry-pi"}:
        return edge_device_runtime_profile()
    raise RuntimeProfileError(f"unknown built-in runtime profile: {name}")


def load_runtime_profile_file(path: str | Path) -> RuntimeProfile:
    payload = _read_json(path)
    return runtime_profile_from_dict(payload)


def save_runtime_profile_file(profile: RuntimeProfile | dict[str, Any], path: str | Path) -> dict[str, Any]:
    payload = runtime_profile_to_dict(profile)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "path": str(destination),
        "profile_id": payload["profile_id"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def load_runtime_profile(
    *,
    builtin: str = "default",
    operator_path: str | Path | None = None,
    operator_profile: RuntimeProfile | dict[str, Any] | None = None,
) -> RuntimeProfile:
    base = get_builtin_runtime_profile(builtin)
    if operator_path is not None:
        operator_profile = _read_json(operator_path)
    if operator_profile is None:
        return base
    return merge_runtime_profiles(base, operator_profile)


def export_runtime_profile(profile: RuntimeProfile | dict[str, Any]) -> str:
    return json.dumps(runtime_profile_to_dict(profile), sort_keys=True)


def import_runtime_profile(text: str) -> RuntimeProfile:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeProfileError(f"invalid runtime profile JSON: {exc}") from exc
    return runtime_profile_from_dict(payload)


def runtime_profile_report(profile: RuntimeProfile | dict[str, Any]) -> dict[str, Any]:
    summary = summarize_runtime_profile(profile)
    validation = validate_runtime_profile(profile)
    return {
        "status": "ok" if validation["ok"] else "invalid",
        "summary": summary,
        "validation": validation,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def _read_json(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeProfileError(f"invalid runtime profile JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeProfileError("runtime profile JSON must be an object")
    return payload
