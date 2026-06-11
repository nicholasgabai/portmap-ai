from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)
from core_engine.scaling.resource_budgets import bounded_percent, bounded_resource_int


EDGE_PROFILE_RECORD_VERSION = 1
EDGE_PROFILE_TYPES = {
    "lightweight_collector",
    "workstation_collector",
    "gateway_collector",
    "branch_collector",
    "enterprise_collector",
    "unknown",
}
EDGE_DEVICE_CLASSES = {"raspberry_pi", "linux_arm", "linux", "macos", "windows", "unknown"}
EDGE_PROFILE_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "worker_deployed": False,
    "runtime_behavior_modified": False,
    "telemetry_collection_changed": False,
    "telemetry_routing_modified": False,
    "infrastructure_provisioned": False,
    "relay_created": False,
}


@dataclass(frozen=True)
class EdgeProfileRecord:
    profile_id: str
    profile_name: str
    profile_type: str
    device_class: str
    cpu_budget_percent: float
    memory_budget_mb: int
    storage_budget_mb: int
    telemetry_budget_per_minute: int
    source_modes: list[str] = field(default_factory=list)
    offline_supported: bool = False
    degraded_supported: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "edge_profile",
            "record_version": EDGE_PROFILE_RECORD_VERSION,
            "profile_id": sanitize_reference(self.profile_id),
            "profile_name": sanitize_text(self.profile_name) or "Unnamed edge profile",
            "profile_type": normalize_edge_profile_type(self.profile_type),
            "device_class": normalize_device_class(self.device_class),
            "cpu_budget_percent": round(bounded_percent(self.cpu_budget_percent), 4),
            "memory_budget_mb": bounded_resource_int(self.memory_budget_mb),
            "storage_budget_mb": bounded_resource_int(self.storage_budget_mb),
            "telemetry_budget_per_minute": bounded_resource_int(self.telemetry_budget_per_minute),
            "source_modes": normalize_edge_source_modes(self.source_modes),
            "offline_supported": bool(self.offline_supported),
            "degraded_supported": bool(self.degraded_supported),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **EDGE_PROFILE_SAFETY_FLAGS,
        }


def build_edge_profile(
    *,
    profile_id: Any = "",
    profile_name: Any = "",
    profile_type: Any = "unknown",
    device_class: Any = "unknown",
    cpu_budget_percent: Any = 0.0,
    memory_budget_mb: Any = 0,
    storage_budget_mb: Any = 0,
    telemetry_budget_per_minute: Any = 0,
    source_modes: Iterable[Any] | None = None,
    offline_supported: Any = False,
    degraded_supported: Any = False,
    advisory_notes: list[Any] | None = None,
) -> EdgeProfileRecord:
    normalized_type = normalize_edge_profile_type(profile_type)
    normalized_device = normalize_device_class(device_class)
    modes = normalize_edge_source_modes(source_modes or ["unknown"])
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    if normalized_device in {"raspberry_pi", "linux_arm"}:
        notes.append("ARM edge readiness is metadata-only; no deployment action is performed")
    if normalized_type in {"gateway_collector", "branch_collector"}:
        notes.append("gateway or branch collector mode is preview-only; routing is unchanged")
    notes.append("edge profile is advisory only; runtime behavior is unchanged")
    safe_name = sanitize_text(profile_name) or f"{normalized_type} edge profile"
    safe_id = sanitize_reference(profile_id)
    if not safe_id:
        safe_id = "edge-profile-" + digest(
            {
                "profile_name": safe_name,
                "profile_type": normalized_type,
                "device_class": normalized_device,
                "cpu_budget_percent": bounded_percent(cpu_budget_percent),
                "memory_budget_mb": bounded_resource_int(memory_budget_mb),
                "storage_budget_mb": bounded_resource_int(storage_budget_mb),
                "telemetry_budget_per_minute": bounded_resource_int(telemetry_budget_per_minute),
                "source_modes": modes,
                "offline_supported": bool(offline_supported),
                "degraded_supported": bool(degraded_supported),
            }
        )[:16]
    return EdgeProfileRecord(
        profile_id=safe_id,
        profile_name=safe_name,
        profile_type=normalized_type,
        device_class=normalized_device,
        cpu_budget_percent=bounded_percent(cpu_budget_percent),
        memory_budget_mb=bounded_resource_int(memory_budget_mb),
        storage_budget_mb=bounded_resource_int(storage_budget_mb),
        telemetry_budget_per_minute=bounded_resource_int(telemetry_budget_per_minute),
        source_modes=modes,
        offline_supported=bool(offline_supported),
        degraded_supported=bool(degraded_supported),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_edge_profile(value: Any) -> EdgeProfileRecord:
    if isinstance(value, EdgeProfileRecord):
        return value
    if not isinstance(value, dict):
        return build_edge_profile(
            profile_name="Invalid edge profile",
            profile_type="unknown",
            device_class="unknown",
            advisory_notes=["invalid edge profile generated from malformed input"],
        )
    try:
        return build_edge_profile(
            profile_id=value.get("profile_id", ""),
            profile_name=value.get("profile_name", value.get("name", "")),
            profile_type=value.get("profile_type", value.get("type", "unknown")),
            device_class=value.get("device_class", value.get("platform", "unknown")),
            cpu_budget_percent=value.get("cpu_budget_percent", 0.0),
            memory_budget_mb=value.get("memory_budget_mb", 0),
            storage_budget_mb=value.get("storage_budget_mb", 0),
            telemetry_budget_per_minute=value.get("telemetry_budget_per_minute", 0),
            source_modes=value.get("source_modes") if isinstance(value.get("source_modes"), list) else [value.get("source_mode", "unknown")],
            offline_supported=value.get("offline_supported", False),
            degraded_supported=value.get("degraded_supported", False),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_edge_profile(
            profile_name="Invalid edge profile",
            profile_type="unknown",
            device_class="unknown",
            advisory_notes=[str(exc)],
        )


def default_edge_profiles(*, source_mode: Any = "unknown") -> list[EdgeProfileRecord]:
    mode = normalize_source_mode(source_mode)
    return [
        build_edge_profile(
            profile_name="Raspberry Pi lightweight collector",
            profile_type="lightweight_collector",
            device_class="raspberry_pi",
            cpu_budget_percent=35.0,
            memory_budget_mb=512,
            storage_budget_mb=1024,
            telemetry_budget_per_minute=300,
            source_modes=[mode],
            offline_supported=True,
            degraded_supported=True,
        ),
        build_edge_profile(
            profile_name="Gateway collector preview",
            profile_type="gateway_collector",
            device_class="linux",
            cpu_budget_percent=50.0,
            memory_budget_mb=1024,
            storage_budget_mb=4096,
            telemetry_budget_per_minute=1200,
            source_modes=[mode],
            offline_supported=True,
            degraded_supported=True,
        ),
    ]


def edge_profile_summary(profiles: Iterable[EdgeProfileRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_edge_profile(profile).to_dict() for profile in list(profiles or [])]
    type_counts: dict[str, int] = {}
    device_counts: dict[str, int] = {}
    source_modes: set[str] = set()
    for row in rows:
        type_counts[row["profile_type"]] = type_counts.get(row["profile_type"], 0) + 1
        device_counts[row["device_class"]] = device_counts.get(row["device_class"], 0) + 1
        source_modes.update(row.get("source_modes", []))
    return {
        "profile_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "device_class_counts": dict(sorted(device_counts.items())),
        "source_modes": sorted(source_modes) or ["unknown"],
        "offline_supported_count": sum(1 for row in rows if row["offline_supported"]),
        "degraded_supported_count": sum(1 for row in rows if row["degraded_supported"]),
        "preview_only": True,
        "destructive_action": False,
    }


def normalize_edge_profile_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in EDGE_PROFILE_TYPES else "unknown"


def normalize_device_class(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"darwin", "mac"}:
        safe_value = "macos"
    if safe_value in {"rpi", "raspberry-pi"}:
        safe_value = "raspberry_pi"
    return safe_value if safe_value in EDGE_DEVICE_CLASSES else "unknown"


def normalize_edge_source_modes(values: Iterable[Any]) -> list[str]:
    modes = {normalize_source_mode(value) for value in values}
    modes = {mode for mode in modes if mode}
    return sorted(modes) or ["unknown"]


def deterministic_edge_profile_json(record: EdgeProfileRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, EdgeProfileRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "EDGE_DEVICE_CLASSES",
    "EDGE_PROFILE_TYPES",
    "EdgeProfileRecord",
    "build_edge_profile",
    "default_edge_profiles",
    "deterministic_edge_profile_json",
    "edge_profile_summary",
    "normalize_device_class",
    "normalize_edge_profile",
    "normalize_edge_profile_type",
    "normalize_edge_source_modes",
]
