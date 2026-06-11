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
from core_engine.scaling.retention_tiers import bounded_int


RESOURCE_BUDGET_RECORD_VERSION = 1
RESOURCE_BUDGET_TYPES = {"edge", "workstation", "server", "enterprise", "unknown"}
RESOURCE_BUDGET_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "runtime_enforcement_enabled": False,
    "telemetry_throttled": False,
    "sampling_changed": False,
    "worker_count_modified": False,
    "runtime_behavior_modified": False,
}


@dataclass(frozen=True)
class ResourceBudgetRecord:
    budget_id: str
    budget_name: str
    budget_type: str
    cpu_budget_percent: float
    memory_budget_mb: int
    storage_budget_mb: int
    telemetry_budget_per_minute: int
    worker_budget_count: int
    source_modes: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "resource_budget",
            "record_version": RESOURCE_BUDGET_RECORD_VERSION,
            "budget_id": sanitize_reference(self.budget_id),
            "budget_name": sanitize_text(self.budget_name) or "Unnamed resource budget",
            "budget_type": normalize_budget_type(self.budget_type),
            "cpu_budget_percent": round(bounded_percent(self.cpu_budget_percent), 4),
            "memory_budget_mb": bounded_resource_int(self.memory_budget_mb),
            "storage_budget_mb": bounded_resource_int(self.storage_budget_mb),
            "telemetry_budget_per_minute": bounded_resource_int(self.telemetry_budget_per_minute),
            "worker_budget_count": bounded_worker_budget(self.worker_budget_count),
            "source_modes": normalize_budget_source_modes(self.source_modes),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **RESOURCE_BUDGET_SAFETY_FLAGS,
        }


def build_resource_budget(
    *,
    budget_id: Any = "",
    budget_name: Any = "",
    budget_type: Any = "unknown",
    cpu_budget_percent: Any = 0.0,
    memory_budget_mb: Any = 0,
    storage_budget_mb: Any = 0,
    telemetry_budget_per_minute: Any = 0,
    worker_budget_count: Any = 0,
    source_modes: Iterable[Any] | None = None,
    advisory_notes: list[Any] | None = None,
) -> ResourceBudgetRecord:
    normalized_type = normalize_budget_type(budget_type)
    modes = normalize_budget_source_modes(source_modes or ["unknown"])
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    if not any(
        [
            bounded_percent(cpu_budget_percent),
            bounded_resource_int(memory_budget_mb),
            bounded_resource_int(storage_budget_mb),
            bounded_resource_int(telemetry_budget_per_minute),
            bounded_worker_budget(worker_budget_count),
        ]
    ):
        notes.append("resource budget has no positive capacity values")
    notes.append("resource budget is advisory only; no runtime enforcement is enabled")
    safe_name = sanitize_text(budget_name) or f"{normalized_type} resource budget"
    safe_id = sanitize_reference(budget_id)
    if not safe_id:
        safe_id = "resource-budget-" + digest(
            {
                "budget_name": safe_name,
                "budget_type": normalized_type,
                "cpu_budget_percent": bounded_percent(cpu_budget_percent),
                "memory_budget_mb": bounded_resource_int(memory_budget_mb),
                "storage_budget_mb": bounded_resource_int(storage_budget_mb),
                "telemetry_budget_per_minute": bounded_resource_int(telemetry_budget_per_minute),
                "worker_budget_count": bounded_worker_budget(worker_budget_count),
                "source_modes": modes,
            }
        )[:16]
    return ResourceBudgetRecord(
        budget_id=safe_id,
        budget_name=safe_name,
        budget_type=normalized_type,
        cpu_budget_percent=bounded_percent(cpu_budget_percent),
        memory_budget_mb=bounded_resource_int(memory_budget_mb),
        storage_budget_mb=bounded_resource_int(storage_budget_mb),
        telemetry_budget_per_minute=bounded_resource_int(telemetry_budget_per_minute),
        worker_budget_count=bounded_worker_budget(worker_budget_count),
        source_modes=modes,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_resource_budget(value: Any) -> ResourceBudgetRecord:
    if isinstance(value, ResourceBudgetRecord):
        return value
    if not isinstance(value, dict):
        return build_resource_budget(
            budget_name="Invalid resource budget",
            budget_type="unknown",
            source_modes=["unknown"],
            advisory_notes=["invalid resource budget generated from malformed input"],
        )
    try:
        return build_resource_budget(
            budget_id=value.get("budget_id", ""),
            budget_name=value.get("budget_name", value.get("name", "")),
            budget_type=value.get("budget_type", value.get("type", "unknown")),
            cpu_budget_percent=value.get("cpu_budget_percent", 0.0),
            memory_budget_mb=value.get("memory_budget_mb", 0),
            storage_budget_mb=value.get("storage_budget_mb", 0),
            telemetry_budget_per_minute=value.get("telemetry_budget_per_minute", 0),
            worker_budget_count=value.get("worker_budget_count", 0),
            source_modes=value.get("source_modes") if isinstance(value.get("source_modes"), list) else [value.get("source_mode", "unknown")],
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_resource_budget(
            budget_name="Invalid resource budget",
            budget_type="unknown",
            advisory_notes=[str(exc)],
        )


def default_resource_budgets(*, source_mode: Any = "unknown") -> list[ResourceBudgetRecord]:
    mode = normalize_source_mode(source_mode)
    return [
        build_resource_budget(
            budget_name="Workstation deployment budget",
            budget_type="workstation",
            cpu_budget_percent=60.0,
            memory_budget_mb=2048,
            storage_budget_mb=10240,
            telemetry_budget_per_minute=3000,
            worker_budget_count=4,
            source_modes=[mode],
        )
    ]


def resource_budget_totals(budgets: Iterable[ResourceBudgetRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_resource_budget(budget).to_dict() for budget in list(budgets or [])]
    type_counts: dict[str, int] = {}
    source_modes: set[str] = set()
    for row in rows:
        type_counts[row["budget_type"]] = type_counts.get(row["budget_type"], 0) + 1
        source_modes.update(row.get("source_modes", []))
    return {
        "budget_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "cpu_budget_percent": sum(float(row["cpu_budget_percent"]) for row in rows),
        "memory_budget_mb": sum(row["memory_budget_mb"] for row in rows),
        "storage_budget_mb": sum(row["storage_budget_mb"] for row in rows),
        "telemetry_budget_per_minute": sum(row["telemetry_budget_per_minute"] for row in rows),
        "worker_budget_count": sum(row["worker_budget_count"] for row in rows),
        "source_modes": sorted(source_modes) or ["unknown"],
        "preview_only": True,
        "destructive_action": False,
    }


def normalize_budget_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in RESOURCE_BUDGET_TYPES else "unknown"


def normalize_budget_source_modes(values: Iterable[Any]) -> list[str]:
    modes = {normalize_source_mode(value) for value in values}
    modes = {mode for mode in modes if mode}
    return sorted(modes) or ["unknown"]


def bounded_percent(value: Any) -> float:
    try:
        return max(0.0, min(100.0, float(value)))
    except Exception:
        return 0.0


def bounded_resource_int(value: Any) -> int:
    return min(10_000_000_000, bounded_int(value))


def bounded_worker_budget(value: Any) -> int:
    return min(10_000, bounded_int(value))


def deterministic_resource_budget_json(record: ResourceBudgetRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, ResourceBudgetRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "RESOURCE_BUDGET_TYPES",
    "ResourceBudgetRecord",
    "bounded_percent",
    "bounded_resource_int",
    "bounded_worker_budget",
    "build_resource_budget",
    "default_resource_budgets",
    "deterministic_resource_budget_json",
    "normalize_budget_source_modes",
    "normalize_budget_type",
    "normalize_resource_budget",
    "resource_budget_totals",
]
