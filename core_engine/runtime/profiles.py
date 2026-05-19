from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.api.app import DEFAULT_LOCAL_API_HOST, DEFAULT_LOCAL_API_PORT
from core_engine.config_validation import validate_config
from core_engine.runtime.session_state import SAFETY_FLAGS, SESSION_MODES


PROFILE_TYPES = frozenset({"default", "edge-device", "operator"})
DEFAULT_COMPONENTS = (
    "runtime_session",
    "scheduler",
    "pipeline",
    "events",
    "storage",
    "api",
    "dashboard",
    "reviews",
    "export",
)


class RuntimeProfileError(ValueError):
    """Raised when a runtime profile is malformed."""


@dataclass(slots=True)
class RuntimeProfile:
    profile_id: str
    name: str
    description: str = ""
    profile_type: str = "operator"
    runtime_mode: str = "dry-run"
    components: list[str] = field(default_factory=lambda: list(DEFAULT_COMPONENTS))
    scheduler: dict[str, Any] = field(default_factory=dict)
    storage: dict[str, Any] = field(default_factory=dict)
    api: dict[str, Any] = field(default_factory=dict)
    dashboard: dict[str, Any] = field(default_factory=dict)
    export: dict[str, Any] = field(default_factory=dict)
    node_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _now())
    updated_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        self.components = _string_list(self.components)
        self.scheduler = dict(self.scheduler or {})
        self.storage = dict(self.storage or {})
        self.api = dict(self.api or {})
        self.dashboard = dict(self.dashboard or {})
        self.export = dict(self.export or {})
        self.node_configs = {
            str(role): dict(config)
            for role, config in dict(self.node_configs or {}).items()
            if isinstance(config, dict)
        }
        self.metadata = dict(self.metadata or {})
        result = validate_runtime_profile(self)
        if not result["ok"]:
            raise RuntimeProfileError("; ".join(result["errors"]))

    def to_dict(self) -> dict[str, Any]:
        return runtime_profile_to_dict(self)


def default_runtime_profile(*, generated_at: str | None = None) -> RuntimeProfile:
    now = generated_at or _now()
    return RuntimeProfile(
        profile_id="runtime-default",
        name="Default Local Runtime",
        description="Balanced local runtime profile for operator-triggered workflows.",
        profile_type="default",
        runtime_mode="dry-run",
        components=list(DEFAULT_COMPONENTS),
        scheduler={
            "enabled": False,
            "poll_interval_seconds": 5,
            "jobs": {
                "health_check": {"enabled": True, "interval_seconds": 60},
                "snapshot_refresh": {"enabled": False, "interval_seconds": 300},
                "event_flush": {"enabled": False, "interval_seconds": 120},
                "policy_review_refresh": {"enabled": False, "interval_seconds": 300},
            },
        },
        storage={
            "enabled": True,
            "backend": "sqlite",
            "database_path": "${PORTMAP_LOCAL_DB}",
            "write_requires_explicit_flag": True,
        },
        api={
            "enabled": False,
            "bind_host": DEFAULT_LOCAL_API_HOST,
            "port": DEFAULT_LOCAL_API_PORT,
            "read_only": True,
        },
        dashboard={
            "enabled": False,
            "provider": "local",
            "static_output_enabled": False,
        },
        export={
            "enabled": True,
            "create_archive": False,
            "output_path": "${PORTMAP_EXPORT_PATH}",
            "redaction_required": True,
        },
        metadata={"resource_profile": "default"},
        created_at=now,
        updated_at=now,
    )


def edge_device_runtime_profile(*, generated_at: str | None = None) -> RuntimeProfile:
    base = default_runtime_profile(generated_at=generated_at).to_dict()
    merged = merge_runtime_profile_dicts(
        base,
        {
            "profile_id": "runtime-edge-device",
            "name": "Edge Device Runtime",
            "description": "Resource-conscious local runtime profile for Raspberry Pi and Linux edge devices.",
            "profile_type": "edge-device",
            "scheduler": {
                "poll_interval_seconds": 15,
                "jobs": {
                    "health_check": {"enabled": True, "interval_seconds": 180},
                    "snapshot_refresh": {"enabled": False, "interval_seconds": 900},
                    "event_flush": {"enabled": False, "interval_seconds": 300},
                    "policy_review_refresh": {"enabled": False, "interval_seconds": 900},
                },
            },
            "dashboard": {"enabled": False, "static_output_enabled": False},
            "metadata": {
                "resource_profile": "edge-device",
                "cpu_budget": "modest",
                "memory_budget": "modest",
            },
        },
    )
    return runtime_profile_from_dict(merged)


def runtime_profile_from_dict(payload: dict[str, Any]) -> RuntimeProfile:
    if not isinstance(payload, dict):
        raise RuntimeProfileError("profile payload must be an object")
    return RuntimeProfile(
        profile_id=str(payload.get("profile_id") or ""),
        name=str(payload.get("name") or ""),
        description=str(payload.get("description") or ""),
        profile_type=str(payload.get("profile_type") or "operator"),
        runtime_mode=str(payload.get("runtime_mode") or "dry-run"),
        components=_string_list(payload.get("components") or []),
        scheduler=dict(payload.get("scheduler") or {}),
        storage=dict(payload.get("storage") or {}),
        api=dict(payload.get("api") or {}),
        dashboard=dict(payload.get("dashboard") or {}),
        export=dict(payload.get("export") or {}),
        node_configs={
            str(role): dict(config)
            for role, config in dict(payload.get("node_configs") or {}).items()
            if isinstance(config, dict)
        },
        metadata=dict(payload.get("metadata") or {}),
        created_at=str(payload.get("created_at") or _now()),
        updated_at=str(payload.get("updated_at") or _now()),
    )


def runtime_profile_to_dict(profile: RuntimeProfile | dict[str, Any]) -> dict[str, Any]:
    if isinstance(profile, dict):
        profile = runtime_profile_from_dict(profile)
    return {
        "profile_id": profile.profile_id,
        "name": profile.name,
        "description": profile.description,
        "profile_type": profile.profile_type,
        "runtime_mode": profile.runtime_mode,
        "components": sorted(set(profile.components)),
        "scheduler": _sorted_dict(profile.scheduler),
        "storage": _sorted_dict(profile.storage),
        "api": _sorted_dict(profile.api),
        "dashboard": _sorted_dict(profile.dashboard),
        "export": _sorted_dict(profile.export),
        "node_configs": _sorted_dict(profile.node_configs),
        "metadata": _sorted_dict(profile.metadata),
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
        **SAFETY_FLAGS,
    }


def merge_runtime_profiles(
    base: RuntimeProfile | dict[str, Any] | None = None,
    operator_profile: RuntimeProfile | dict[str, Any] | None = None,
) -> RuntimeProfile:
    base_payload = runtime_profile_to_dict(base or default_runtime_profile())
    override_payload = runtime_profile_to_dict(operator_profile) if isinstance(operator_profile, RuntimeProfile) else dict(operator_profile or {})
    merged = merge_runtime_profile_dicts(base_payload, override_payload)
    merged["profile_type"] = str(merged.get("profile_type") or "operator")
    merged["updated_at"] = str(override_payload.get("updated_at") or _now())
    return runtime_profile_from_dict(merged)


def merge_runtime_profile_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in dict(override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_runtime_profile_dicts(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def validate_runtime_profile(profile: RuntimeProfile | dict[str, Any]) -> dict[str, Any]:
    payload = _raw_profile_dict(profile)
    errors: list[str] = []
    warnings: list[str] = []

    if not str(payload.get("profile_id") or "").strip():
        errors.append("profile_id is required")
    if not str(payload.get("name") or "").strip():
        errors.append("name is required")
    if payload.get("profile_type") not in PROFILE_TYPES:
        errors.append("profile_type must be one of: default, edge-device, operator")
    if payload.get("runtime_mode") not in SESSION_MODES:
        errors.append("runtime_mode must be one of: dry-run, local-write, service-preview")

    components = payload.get("components")
    if not isinstance(components, list) or not all(isinstance(item, str) and item for item in components):
        errors.append("components must be a list of non-empty strings")

    _validate_scheduler(payload.get("scheduler"), errors)
    _validate_storage(payload.get("storage"), errors)
    _validate_api(payload.get("api"), errors)
    _validate_dashboard(payload.get("dashboard"), errors)
    _validate_export(payload.get("export"), errors)

    for role, config in dict(payload.get("node_configs") or {}).items():
        if not isinstance(config, dict):
            errors.append(f"node_configs.{role} must be an object")
            continue
        result = validate_config(config, expected_role=str(role))
        errors.extend(f"node_configs.{role}: {message}" for message in result.errors)
        warnings.extend(f"node_configs.{role}: {message}" for message in result.warnings)

    return {
        "ok": not errors,
        "status": "valid" if not errors else "invalid",
        "errors": errors,
        "warnings": warnings,
        **SAFETY_FLAGS,
    }


def summarize_runtime_profile(profile: RuntimeProfile | dict[str, Any]) -> dict[str, Any]:
    payload = runtime_profile_to_dict(profile)
    validation = validate_runtime_profile(payload)
    jobs = dict((payload.get("scheduler") or {}).get("jobs") or {})
    enabled_jobs = sorted(name for name, row in jobs.items() if isinstance(row, dict) and row.get("enabled") is True)
    return {
        "profile_id": payload["profile_id"],
        "name": payload["name"],
        "profile_type": payload["profile_type"],
        "runtime_mode": payload["runtime_mode"],
        "component_count": len(payload["components"]),
        "components": payload["components"],
        "scheduler_enabled": bool((payload.get("scheduler") or {}).get("enabled", False)),
        "enabled_job_count": len(enabled_jobs),
        "enabled_jobs": enabled_jobs,
        "storage_backend": str((payload.get("storage") or {}).get("backend") or ""),
        "api_bind_host": str((payload.get("api") or {}).get("bind_host") or ""),
        "api_port": int((payload.get("api") or {}).get("port") or 0),
        "dashboard_enabled": bool((payload.get("dashboard") or {}).get("enabled", False)),
        "export_enabled": bool((payload.get("export") or {}).get("enabled", False)),
        "validation": validation,
        **SAFETY_FLAGS,
    }


def _validate_scheduler(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("scheduler must be an object")
        return
    _require_bool(value, "enabled", "scheduler", errors)
    _require_positive_number(value, "poll_interval_seconds", "scheduler", errors)
    jobs = value.get("jobs")
    if jobs is None:
        return
    if not isinstance(jobs, dict):
        errors.append("scheduler.jobs must be an object")
        return
    for name, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"scheduler.jobs.{name} must be an object")
            continue
        _require_bool(job, "enabled", f"scheduler.jobs.{name}", errors)
        _require_positive_number(job, "interval_seconds", f"scheduler.jobs.{name}", errors)


def _validate_storage(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("storage must be an object")
        return
    _require_bool(value, "enabled", "storage", errors)
    if value.get("backend") not in {"sqlite"}:
        errors.append("storage.backend must be sqlite")
    _require_string(value, "database_path", "storage", errors)
    _require_bool(value, "write_requires_explicit_flag", "storage", errors)


def _validate_api(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("api must be an object")
        return
    _require_bool(value, "enabled", "api", errors)
    _require_bool(value, "read_only", "api", errors)
    _require_string(value, "bind_host", "api", errors)
    port = value.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        errors.append("api.port must be an integer between 1 and 65535")


def _validate_dashboard(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("dashboard must be an object")
        return
    _require_bool(value, "enabled", "dashboard", errors)
    _require_bool(value, "static_output_enabled", "dashboard", errors)
    _require_string(value, "provider", "dashboard", errors)


def _validate_export(value: Any, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append("export must be an object")
        return
    _require_bool(value, "enabled", "export", errors)
    _require_bool(value, "create_archive", "export", errors)
    _require_bool(value, "redaction_required", "export", errors)
    _require_string(value, "output_path", "export", errors)


def _require_bool(value: dict[str, Any], key: str, prefix: str, errors: list[str]) -> None:
    if key in value and not isinstance(value.get(key), bool):
        errors.append(f"{prefix}.{key} must be a boolean")


def _require_string(value: dict[str, Any], key: str, prefix: str, errors: list[str]) -> None:
    if not isinstance(value.get(key), str) or not value.get(key):
        errors.append(f"{prefix}.{key} must be a non-empty string")


def _require_positive_number(value: dict[str, Any], key: str, prefix: str, errors: list[str]) -> None:
    item = value.get(key)
    if not isinstance(item, (int, float)) or isinstance(item, bool) or item <= 0:
        errors.append(f"{prefix}.{key} must be greater than zero")


def _raw_profile_dict(profile: RuntimeProfile | dict[str, Any]) -> dict[str, Any]:
    if isinstance(profile, RuntimeProfile):
        return {
            "profile_id": profile.profile_id,
            "name": profile.name,
            "description": profile.description,
            "profile_type": profile.profile_type,
            "runtime_mode": profile.runtime_mode,
            "components": profile.components,
            "scheduler": profile.scheduler,
            "storage": profile.storage,
            "api": profile.api,
            "dashboard": profile.dashboard,
            "export": profile.export,
            "node_configs": profile.node_configs,
            "metadata": profile.metadata,
            "created_at": profile.created_at,
            "updated_at": profile.updated_at,
        }
    return dict(profile)


def _sorted_dict(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        if isinstance(item, dict):
            result[key] = _sorted_dict(item)
        elif isinstance(item, list):
            result[key] = list(item)
        else:
            result[key] = item
    return result


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item) for item in value if str(item).strip()})


def _now() -> str:
    return datetime.now(UTC).isoformat()
