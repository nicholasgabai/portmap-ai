from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.plugins.manifest import SAFETY_FLAGS, PluginManifestError, normalize_plugin_manifest, validate_plugin_manifest


class PluginRegistryError(ValueError):
    """Raised when the local plugin registry rejects an operation."""


def create_plugin_registry(
    *,
    allowlisted_paths: Iterable[str | Path] | None = None,
    plugins: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    resolved_paths = [_resolve_path(path) for path in allowlisted_paths or []]
    registry = {
        "registry_id": _stable_id("plugin-registry", [path.as_posix() for path in resolved_paths]),
        "plugin_count": 0,
        "plugins": {},
        "allowlisted_path_count": len(resolved_paths),
        "_allowlisted_paths": resolved_paths,
        "created_at": _now(),
        "updated_at": _now(),
        **SAFETY_FLAGS,
    }
    for manifest in plugins or []:
        register_plugin(registry, manifest)
    return registry


def load_manifest_file(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PluginRegistryError(f"manifest could not be loaded: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise PluginRegistryError("manifest file must contain a JSON object")
    return data


def collect_plugin_manifests(directory: str | Path, *, pattern: str = "*.json", max_manifests: int = 64) -> dict[str, Any]:
    base = Path(directory)
    manifests: list[dict[str, Any]] = []
    errors: list[str] = []
    if not base.exists() or not base.is_dir():
        return _collection_result(manifests, ["manifest directory does not exist or is not a directory"])
    for manifest_path in sorted(base.glob(pattern))[:max_manifests]:
        try:
            manifests.append(load_manifest_file(manifest_path))
        except PluginRegistryError as exc:
            errors.append(str(exc))
    if len(list(base.glob(pattern))) > max_manifests:
        errors.append(f"manifest count exceeds max_manifests {max_manifests}")
    return _collection_result(manifests, errors)


def register_plugin(
    registry: dict[str, Any],
    manifest: dict[str, Any],
    *,
    plugin_path: str | Path | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    _ensure_registry(registry)
    if plugin_path is not None and not _is_allowlisted(plugin_path, registry.get("_allowlisted_paths") or []):
        raise PluginRegistryError("plugin path is not allowlisted")
    try:
        normalized = normalize_plugin_manifest(manifest)
    except PluginManifestError as exc:
        raise PluginRegistryError(str(exc)) from exc
    state = "enabled" if enabled and normalized.get("lifecycle_state") != "disabled" else "disabled"
    entry = {
        "plugin_id": normalized["plugin_id"],
        "manifest": normalized,
        "state": state,
        "lifecycle_state": normalized.get("lifecycle_state", "registered"),
        "registered_at": _now(),
        "updated_at": _now(),
        "source_path_ref": _path_ref(plugin_path) if plugin_path is not None else None,
        "_plugin_path": _resolve_path(plugin_path) if plugin_path is not None else None,
        **SAFETY_FLAGS,
    }
    registry["plugins"][entry["plugin_id"]] = entry
    registry["plugin_count"] = len(registry["plugins"])
    registry["updated_at"] = _now()
    return entry


def list_plugins(registry: dict[str, Any], *, include_disabled: bool = True) -> list[dict[str, Any]]:
    _ensure_registry(registry)
    rows = []
    for entry in registry["plugins"].values():
        if not include_disabled and entry.get("state") == "disabled":
            continue
        rows.append(_public_entry(entry))
    return sorted(rows, key=lambda row: row["plugin_id"])


def get_plugin(registry: dict[str, Any], plugin_id: str) -> dict[str, Any] | None:
    _ensure_registry(registry)
    entry = registry["plugins"].get(plugin_id)
    if entry is None:
        return None
    return _public_entry(entry)


def summarize_registry(registry: dict[str, Any]) -> dict[str, Any]:
    _ensure_registry(registry)
    states: dict[str, int] = {}
    capabilities: set[str] = set()
    for entry in registry["plugins"].values():
        states[str(entry.get("state") or "unknown")] = states.get(str(entry.get("state") or "unknown"), 0) + 1
        capabilities.update(str(item) for item in (entry.get("manifest") or {}).get("capabilities") or [])
    return {
        "registry_id": registry.get("registry_id"),
        "plugin_count": len(registry["plugins"]),
        "state_counts": dict(sorted(states.items())),
        "capabilities": sorted(capabilities),
        "allowlisted_path_count": int(registry.get("allowlisted_path_count") or 0),
        "local_only": True,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def _collection_result(manifests: list[dict[str, Any]], errors: list[str]) -> dict[str, Any]:
    validation_results = [validate_plugin_manifest(manifest) for manifest in manifests]
    return {
        "ok": not errors and all(result["ok"] for result in validation_results),
        "status": "ok" if not errors else "partial",
        "manifest_count": len(manifests),
        "manifests": manifests,
        "validation_results": validation_results,
        "errors": errors,
        **SAFETY_FLAGS,
    }


def _ensure_registry(registry: dict[str, Any]) -> None:
    if not isinstance(registry, dict) or not isinstance(registry.get("plugins"), dict):
        raise PluginRegistryError("registry must be created by create_plugin_registry")


def _is_allowlisted(path: str | Path, allowlisted_paths: Iterable[Path]) -> bool:
    resolved = _resolve_path(path)
    for base in allowlisted_paths:
        if resolved == base or _is_relative_to(resolved, base):
            return True
    return False


def _public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in entry.items()
        if not key.startswith("_")
    }


def _path_ref(path: str | Path | None) -> str | None:
    if path is None:
        return None
    resolved = _resolve_path(path)
    return _stable_id("path", resolved.name, resolved.suffix)


def _resolve_path(path: str | Path | None) -> Path:
    if path is None:
        raise PluginRegistryError("path is required")
    return Path(path).expanduser().resolve()


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
