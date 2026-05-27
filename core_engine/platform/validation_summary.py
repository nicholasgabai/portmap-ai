from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.platform.capture_readiness import build_cross_platform_capture_readiness_report
from core_engine.platform.filesystem_safety import build_filesystem_safety_report
from core_engine.platform.firewall_readiness import build_cross_platform_firewall_readiness_report
from core_engine.platform.runtime_detection import build_platform_runtime_record, build_runtime_compatibility_report
from core_engine.platform.windows_runtime import build_windows_runtime_compatibility_report


PLATFORM_VALIDATION_RECORD_VERSION = 1

PLATFORM_VALIDATION_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "administrator_controlled": True,
    "advisory": True,
    "dry_run": True,
    "preview_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "automatic_changes": False,
    "service_installed": False,
    "service_started": False,
    "firewall_rules_changed": False,
    "packet_capture_enabled": False,
    "capture_loop_started": False,
    "admin_elevation_requested": False,
    "dashboard_safe": True,
    "api_compatible": True,
}

DEFAULT_PLATFORM_FIXTURES = (
    {"platform_family": "macos", "system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64"},
    {"platform_family": "linux", "system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64"},
    {"platform_family": "raspberry-pi-linux-arm", "system": "Linux", "release": "linux-arm-release-placeholder", "machine": "aarch64"},
    {"platform_family": "windows", "system": "Windows", "release": "windows-release-placeholder", "machine": "AMD64"},
)


def build_cross_platform_validation_report(
    *,
    platform_inputs: Iterable[dict[str, Any]] | None = None,
    runtime_reports: dict[str, dict[str, Any]] | None = None,
    capture_readiness: dict[str, dict[str, Any]] | None = None,
    firewall_readiness: dict[str, dict[str, Any]] | None = None,
    filesystem_safety: dict[str, dict[str, Any]] | None = None,
    windows_compatibility: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a unified dry-run cross-platform compatibility validation report."""
    timestamp = generated_at or _now()
    rows = [
        build_platform_validation_summary(
            platform_input=platform_input,
            runtime_report=(runtime_reports or {}).get(str(platform_input.get("platform_family") or "")),
            capture_readiness=(capture_readiness or {}).get(str(platform_input.get("platform_family") or "")),
            firewall_readiness=(firewall_readiness or {}).get(str(platform_input.get("platform_family") or "")),
            filesystem_safety=(filesystem_safety or {}).get(str(platform_input.get("platform_family") or "")),
            windows_compatibility=windows_compatibility if str(platform_input.get("platform_family") or "") == "windows" else None,
            runtime_health=runtime_health,
            gateway_validation=gateway_validation,
            service_mode=service_mode,
            generated_at=timestamp,
        )
        for platform_input in (list(platform_inputs or DEFAULT_PLATFORM_FIXTURES))
    ]
    aggregate = summarize_cross_platform_validation(rows, generated_at=timestamp)
    recommendations = build_operator_recommendations(rows, generated_at=timestamp)
    return {
        "record_type": "cross_platform_validation_report",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "report_id": "cross-platform-validation-" + _digest({"generated_at": timestamp, "platforms": rows, "aggregate": aggregate})[:16],
        "generated_at": timestamp,
        "platforms": sorted(rows, key=lambda item: str(item.get("platform_family") or "")),
        "summary": aggregate,
        "operator_recommendations": recommendations,
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_platform_validation_summary(
    *,
    platform_input: dict[str, Any],
    runtime_report: dict[str, Any] | None = None,
    capture_readiness: dict[str, Any] | None = None,
    firewall_readiness: dict[str, Any] | None = None,
    filesystem_safety: dict[str, Any] | None = None,
    windows_compatibility: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    service_mode: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    platform_record = build_platform_runtime_record(
        platform_info={
            "system": platform_input.get("system"),
            "release": platform_input.get("release"),
            "machine": platform_input.get("machine"),
            "python_version": platform_input.get("python_version") or "3.11.5",
        },
        is_admin=bool(platform_input.get("is_admin", False)),
        generated_at=timestamp,
    )
    platform_family = str(platform_record.get("platform_family") or platform_input.get("platform_family") or "unknown")
    runtime = runtime_report or build_runtime_compatibility_report(
        platform_info={
            "system": platform_input.get("system"),
            "release": platform_input.get("release"),
            "machine": platform_input.get("machine"),
            "python_version": platform_input.get("python_version") or "3.11.5",
        },
        is_admin=bool(platform_input.get("is_admin", False)),
        runtime_health=runtime_health,
        service_mode=service_mode,
        gateway_validation=gateway_validation,
        generated_at=timestamp,
    )
    capture = capture_readiness or build_cross_platform_capture_readiness_report(
        platform_record=platform_record,
        interfaces={},
        runtime_health=runtime_health,
        gateway_validation=gateway_validation,
        generated_at=timestamp,
    )
    firewall = firewall_readiness or build_cross_platform_firewall_readiness_report(
        platform_record=platform_record,
        runtime_health=runtime_health,
        gateway_validation=gateway_validation,
        generated_at=timestamp,
    )
    filesystem = filesystem_safety or build_filesystem_safety_report(
        platform_record=platform_record,
        candidate_paths=[],
        public_doc_records=[],
        generated_at=timestamp,
    )
    windows = windows_compatibility
    if platform_family == "windows" and windows is None:
        windows = build_windows_runtime_compatibility_report(
            platform_info={
                "system": "Windows",
                "release": platform_input.get("release") or "windows-release-placeholder",
                "machine": platform_input.get("machine") or "AMD64",
                "python_version": platform_input.get("python_version") or "3.11.5",
            },
            is_admin=bool(platform_input.get("is_admin", False)),
            service_mode=service_mode,
            generated_at=timestamp,
        )
    components = {
        "runtime_detection": _component_status(runtime),
        "packet_capture": _component_status(capture),
        "firewall_provider": _component_status(firewall),
        "filesystem_export": _component_status(filesystem),
    }
    if platform_family == "windows":
        components["windows_compatibility"] = _component_status(windows)
    status = _aggregate_status(components.values())
    warnings = sorted(
        set(
            _record_warnings(runtime)
            + _record_warnings(capture)
            + _record_warnings(firewall)
            + _record_warnings(filesystem)
            + _record_warnings(windows)
        )
    )
    return {
        "record_type": "platform_validation_summary",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "generated_at": timestamp,
        "platform_family": platform_family,
        "status": status,
        "component_statuses": dict(sorted(components.items())),
        "component_count": len(components),
        "supported_count": sum(1 for value in components.values() if value == "supported"),
        "degraded_count": sum(1 for value in components.values() if value == "degraded"),
        "unavailable_count": sum(1 for value in components.values() if value == "unavailable"),
        "unknown_count": sum(1 for value in components.values() if value == "unknown"),
        "warnings": warnings,
        "operator_summary": _platform_operator_summary(platform_family, status),
        "source_refs": _source_refs(runtime, capture, firewall, filesystem, windows),
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def summarize_cross_platform_validation(platforms: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in platforms or [] if isinstance(row, dict)]
    counts = _status_counts(row.get("status") for row in rows)
    status = _aggregate_status(row.get("status") for row in rows)
    warnings = sorted({warning for row in rows for warning in row.get("warnings") or []})
    return {
        "record_type": "cross_platform_validation_summary",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "platform_count": len(rows),
        "supported_count": counts["supported"],
        "degraded_count": counts["degraded"],
        "unavailable_count": counts["unavailable"],
        "unknown_count": counts["unknown"],
        "platforms_by_status": counts,
        "warnings": warnings,
        "operator_summary": _aggregate_operator_summary(status),
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_operator_recommendations(platforms: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    recommendations = []
    for platform_row in platforms or []:
        platform_family = str(platform_row.get("platform_family") or "unknown")
        for component, status in sorted(dict(platform_row.get("component_statuses") or {}).items()):
            normalized = _normalize_status(status)
            if normalized != "supported":
                recommendations.append(
                    {
                        "record_type": "platform_validation_recommendation",
                        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
                        "generated_at": timestamp,
                        "platform_family": platform_family,
                        "component": component,
                        "status": normalized,
                        "recommendation": _component_recommendation(component, normalized),
                        "operator_review_required": True,
                        **PLATFORM_VALIDATION_SAFETY_FLAGS,
                    }
                )
    return {
        "record_type": "platform_validation_recommendations",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "generated_at": timestamp,
        "recommendation_count": len(recommendations),
        "items": recommendations,
        "operator_review_required": bool(recommendations),
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_cli_table_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for platform_row in report.get("platforms") or []:
        if not isinstance(platform_row, dict):
            continue
        components = dict(platform_row.get("component_statuses") or {})
        rows.append(
            {
                "platform": str(platform_row.get("platform_family") or "unknown"),
                "status": str(platform_row.get("status") or "unknown"),
                "runtime": str(components.get("runtime_detection") or "unknown"),
                "capture": str(components.get("packet_capture") or "unknown"),
                "firewall": str(components.get("firewall_provider") or "unknown"),
                "filesystem": str(components.get("filesystem_export") or "unknown"),
                "windows": str(components.get("windows_compatibility") or "n/a"),
                "review": "yes" if str(platform_row.get("status") or "") != "supported" else "no",
            }
        )
    return sorted(rows, key=lambda item: item["platform"])


def export_validation_summary_json(report: dict[str, Any]) -> str:
    return deterministic_validation_summary_json(report)


def deterministic_validation_summary_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _component_status(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    status = record.get("status")
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    if status is None:
        status = summary.get("status")
    return _normalize_status(status)


def _normalize_status(status: Any) -> str:
    value = str(status or "unknown")
    if value in {"ok", "ready", "valid"}:
        return "supported"
    if value in {"review_required", "blocked", "unsafe"}:
        return "degraded"
    if value in {"supported", "degraded", "unavailable", "unknown"}:
        return value
    return "unknown"


def _aggregate_status(statuses: Iterable[Any]) -> str:
    rows = [_normalize_status(status) for status in statuses]
    if not rows:
        return "unknown"
    if any(status == "unavailable" for status in rows):
        return "unavailable" if all(status == "unavailable" for status in rows) else "degraded"
    if any(status == "degraded" for status in rows):
        return "degraded"
    if any(status == "unknown" for status in rows):
        return "unknown"
    return "supported"


def _status_counts(statuses: Iterable[Any]) -> dict[str, int]:
    rows = [_normalize_status(status) for status in statuses]
    return {status: sum(1 for row in rows if row == status) for status in ("degraded", "supported", "unavailable", "unknown")}


def _record_warnings(record: dict[str, Any] | None) -> list[str]:
    if not isinstance(record, dict):
        return []
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    warnings = list(record.get("warnings") or []) + list(summary.get("warnings") or [])
    return [str(item) for item in warnings if str(item)]


def _source_refs(*records: dict[str, Any] | None) -> list[str]:
    refs: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in ("report_id", "path_summary_id", "provider_summary_id", "capability_summary_id"):
            if record.get(key):
                refs.append(str(record[key]))
    return sorted(set(refs))


def _platform_operator_summary(platform_family: str, status: str) -> str:
    if status == "supported":
        return f"{platform_family} compatibility is supported for dry-run validation."
    if status == "degraded":
        return f"{platform_family} compatibility requires operator review for one or more capabilities."
    if status == "unavailable":
        return f"{platform_family} compatibility is unavailable for one or more required capabilities."
    return f"{platform_family} compatibility is unknown and requires operator review."


def _aggregate_operator_summary(status: str) -> str:
    if status == "supported":
        return "All platform compatibility summaries are supported for dry-run use."
    if status == "degraded":
        return "One or more platform compatibility summaries require operator review."
    if status == "unavailable":
        return "One or more platform compatibility summaries are unavailable."
    return "Cross-platform compatibility requires operator review."


def _component_recommendation(component: str, status: str) -> str:
    if component == "packet_capture":
        return "Review capture backend availability and manual packet-capture permissions before enabling future capture."
    if component == "firewall_provider":
        return "Review provider availability and keep firewall behavior dry-run until explicitly approved."
    if component == "filesystem_export":
        return "Review export paths and artifact exclusions before staging or publishing files."
    if component == "windows_compatibility":
        return "Review Windows service, process/socket, and path fallbacks before Windows runtime use."
    return f"Review {component} compatibility because its status is {status}."


def _digest(payload: Any) -> str:
    return sha256(deterministic_validation_summary_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "DEFAULT_PLATFORM_FIXTURES",
    "PLATFORM_VALIDATION_SAFETY_FLAGS",
    "build_cli_table_rows",
    "build_cross_platform_validation_report",
    "build_operator_recommendations",
    "build_platform_validation_summary",
    "deterministic_validation_summary_json",
    "export_validation_summary_json",
    "summarize_cross_platform_validation",
]
