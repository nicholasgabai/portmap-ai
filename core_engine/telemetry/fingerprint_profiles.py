from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.temporal_anomalies import TEMPORAL_ANOMALY_SAFETY_FLAGS


SERVICE_FINGERPRINT_PROFILE_RECORD_VERSION = 1
DEFAULT_MAX_SERVICE_FINGERPRINT_PROFILES = 500
DEFAULT_SERVICE_FINGERPRINT_MATURITY_THRESHOLD = 3

SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS = {
    **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    "metadata_only": True,
    "privacy_preserving": True,
    "credentials_stored": False,
    "dns_query_contents_stored": False,
    "full_dns_queries_stored": False,
    "command_line_stored": False,
    "user_documents_collected": False,
    "enforcement_actions_created": False,
    "firewall_changes": False,
    "external_services_called": False,
}


class ServiceFingerprintProfileError(ValueError):
    """Raised when service fingerprint profile input is malformed."""


def build_fingerprint_profile_records(
    fingerprints: Iterable[dict[str, Any]],
    *,
    previous_profiles: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_profiles: int = DEFAULT_MAX_SERVICE_FINGERPRINT_PROFILES,
    maturity_threshold: int = DEFAULT_SERVICE_FINGERPRINT_MATURITY_THRESHOLD,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    if int(max_profiles) <= 0:
        raise ServiceFingerprintProfileError("max_profiles must be positive")
    if int(maturity_threshold) <= 0:
        raise ServiceFingerprintProfileError("maturity_threshold must be positive")

    grouped = _group_by_key(_rows(fingerprints))
    previous = _previous_index(previous_profiles)
    profiles = [
        _build_profile(
            fingerprint_key=key,
            fingerprints=rows,
            previous=previous.get(key),
            generated_at=timestamp,
            maturity_threshold=int(maturity_threshold),
        )
        for key, rows in grouped.items()
    ]
    for key, previous_profile in previous.items():
        if key not in grouped:
            profiles.append(_build_dormant_profile(fingerprint_key=key, previous=previous_profile, generated_at=timestamp))

    profiles = sorted(profiles, key=lambda item: (str(item.get("display_label") or ""), str(item.get("fingerprint_key") or "")))
    dropped = max(0, len(profiles) - int(max_profiles))
    selected = profiles[: int(max_profiles)]
    for row in selected:
        row["bounded_retention_applied"] = dropped > 0
        row["dropped_profile_count"] = dropped
    return selected


def classify_service_fingerprint_profile(
    *,
    fingerprints: Iterable[dict[str, Any]],
    previous_profile: dict[str, Any] | None = None,
    maturity_threshold: int = DEFAULT_SERVICE_FINGERPRINT_MATURITY_THRESHOLD,
) -> dict[str, Any]:
    rows = _rows(fingerprints)
    previous = dict(previous_profile or {})
    count = len(rows)
    unusual = any(bool(row.get("unusual_combination")) for row in rows)
    low_confidence = any(float(row.get("confidence") or 0.0) < 0.45 for row in rows)
    previous_seen = bool(previous)
    previous_dormant = bool(previous.get("dormant") or previous.get("behavior_state") == "dormant")
    stable = count >= int(maturity_threshold) and not unusual and not low_confidence
    labels: set[str] = set()
    if stable:
        labels.add("stable_service_behavior")
    if not previous_seen and count < int(maturity_threshold):
        labels.add("newly_observed_service")
    if any("uncommon_protocol_binding" in row.get("classification_labels", []) for row in rows):
        labels.add("uncommon_protocol_binding")
    if any("unusual_process_port_pair" in row.get("classification_labels", []) for row in rows):
        labels.add("unusual_process_port_pair")
    if previous_dormant and count:
        labels.add("dormant_service_returned")
    if previous_seen and not unusual and not low_confidence:
        labels.add("baseline_consistent")
    if not labels:
        labels.add("baseline_consistent" if previous_seen else "newly_observed_service")

    if count == 0 and previous_seen:
        state = "dormant"
    elif stable:
        state = "stable"
    elif previous_seen:
        state = "recurring"
    else:
        state = "new"
    return {
        "record_type": "service_fingerprint_profile_classification",
        "behavior_state": state,
        "classification_labels": sorted(labels),
        "stable_service_profile": stable,
        "unusual_combination": unusual,
        "low_confidence_warning": low_confidence,
        "dormant_reappeared": previous_dormant and count > 0,
        "dormant": state == "dormant",
        "maturity_threshold": int(maturity_threshold),
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }


def score_service_fingerprint_confidence(
    *,
    recurrence_count: int,
    timing_consistency: float,
    protocol_stability: float,
    port_consistency: float,
    historical_maturity: float,
    observation_density: float,
) -> float:
    score = 0.1
    score += min(0.22, int(recurrence_count) * 0.055)
    score += min(0.18, max(0.0, min(1.0, float(timing_consistency))) * 0.18)
    score += min(0.16, max(0.0, min(1.0, float(protocol_stability))) * 0.16)
    score += min(0.16, max(0.0, min(1.0, float(port_consistency))) * 0.16)
    score += min(0.18, max(0.0, min(1.0, float(historical_maturity))) * 0.18)
    score += min(0.1, max(0.0, min(1.0, float(observation_density))) * 0.1)
    return round(min(1.0, score), 3)


def summarize_service_fingerprint_profiles(
    profiles: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(profiles)
    return {
        "record_type": "service_fingerprint_profile_summary",
        "record_version": SERVICE_FINGERPRINT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "profile_count": len(rows),
        "stable_profile_count": sum(1 for row in rows if row.get("stable_service_profile")),
        "new_profile_count": sum(1 for row in rows if row.get("behavior_state") == "new"),
        "dormant_profile_count": sum(1 for row in rows if row.get("dormant")),
        "dormant_reappeared_count": sum(1 for row in rows if row.get("dormant_reappeared")),
        "unusual_combination_count": sum(1 for row in rows if row.get("unusual_combination")),
        "low_confidence_count": sum(1 for row in rows if row.get("low_confidence_warning")),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_behavior_state": _count_by(rows, "behavior_state"),
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }


def build_service_fingerprint_dashboard_record(
    *,
    summary: dict[str, Any],
    profiles: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(profiles)
    review = bool(int(summary.get("unusual_combination_count") or 0) or int(summary.get("dormant_reappeared_count") or 0) or int(summary.get("low_confidence_count") or 0))
    return {
        "record_type": "service_fingerprint_dashboard",
        "panel": "service_fingerprints",
        "status": "review_required" if review else "ok",
        "generated_at": generated_at or _now(),
        "metrics": {
            "profile_count": int(summary.get("profile_count") or 0),
            "stable_profile_count": int(summary.get("stable_profile_count") or 0),
            "new_profile_count": int(summary.get("new_profile_count") or 0),
            "dormant_reappeared_count": int(summary.get("dormant_reappeared_count") or 0),
            "unusual_combination_count": int(summary.get("unusual_combination_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "by_behavior_state": dict(summary.get("by_behavior_state") or {}),
        "rows": [
            {
                "profile_id": row.get("profile_id"),
                "display_label": row.get("display_label"),
                "behavior_state": row.get("behavior_state"),
                "classification_labels": list(row.get("classification_labels") or []),
                "observation_count": int(row.get("observation_count") or 0),
                "confidence": float(row.get("confidence") or 0.0),
            }
            for row in sorted(rows, key=lambda item: (str(item.get("behavior_state") or ""), str(item.get("display_label") or "")))[:50]
        ],
        "recommended_review": review,
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }


def build_service_fingerprint_api_response(
    *,
    summary: dict[str, Any],
    profiles: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "service_fingerprint_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "profiles": _rows(profiles),
        "dashboard": dict(dashboard),
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }


def build_service_fingerprint_export_record(
    *,
    summary: dict[str, Any],
    profiles: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(profiles)
    payload = {
        "record_type": "service_fingerprint_export_summary",
        "record_version": SERVICE_FINGERPRINT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "profiles": len(rows),
            "stable_profiles": int(summary.get("stable_profile_count") or 0),
            "unusual_combinations": int(summary.get("unusual_combination_count") or 0),
            "dormant_reappeared": int(summary.get("dormant_reappeared_count") or 0),
        },
        "profile_ids": [str(row.get("profile_id") or "") for row in rows],
        "digest": "",
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"record_counts": payload["record_counts"], "profile_ids": payload["profile_ids"]})
    return payload


def deterministic_service_fingerprint_profile_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _build_profile(
    *,
    fingerprint_key: str,
    fingerprints: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    generated_at: str,
    maturity_threshold: int,
) -> dict[str, Any]:
    rows = sorted(fingerprints, key=lambda item: str(item.get("observed_at") or item.get("generated_at") or ""))
    first_seen = min((str(row.get("observed_at") or row.get("generated_at") or "") for row in rows), default="")
    last_seen = max((str(row.get("observed_at") or row.get("generated_at") or "") for row in rows), default="")
    classification = classify_service_fingerprint_profile(fingerprints=rows, previous_profile=previous, maturity_threshold=maturity_threshold)
    confidence = _profile_confidence(rows=rows, previous=previous, maturity_threshold=maturity_threshold)
    profile = {
        "record_type": "service_fingerprint_profile",
        "record_version": SERVICE_FINGERPRINT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at,
        "fingerprint_key": fingerprint_key,
        "display_label": _display_label(rows, previous=previous),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observation_count": len(rows),
        "recurrence_count": len(rows),
        "expected_behavior_summary": _expected_behavior_summary(rows),
        "source_refs": sorted({str(ref) for row in rows for ref in row.get("source_refs", []) if ref}),
        "confidence": confidence,
        "bounded_retention_applied": False,
        "dropped_profile_count": 0,
        **classification,
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }
    profile["profile_id"] = "service-fingerprint-profile-" + _digest({"fingerprint_key": fingerprint_key})[:16]
    return profile


def _build_dormant_profile(*, fingerprint_key: str, previous: dict[str, Any], generated_at: str) -> dict[str, Any]:
    confidence = round(max(0.1, float(previous.get("confidence") or 0.2) * 0.5), 3)
    profile = {
        "record_type": "service_fingerprint_profile",
        "record_version": SERVICE_FINGERPRINT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at,
        "fingerprint_key": fingerprint_key,
        "display_label": str(previous.get("display_label") or fingerprint_key),
        "first_seen": str(previous.get("first_seen") or ""),
        "last_seen": str(previous.get("last_seen") or ""),
        "observation_count": int(previous.get("observation_count") or 0),
        "recurrence_count": int(previous.get("recurrence_count") or previous.get("observation_count") or 0),
        "expected_behavior_summary": dict(previous.get("expected_behavior_summary") or {}),
        "behavior_state": "dormant",
        "classification_labels": ["baseline_consistent"],
        "stable_service_profile": False,
        "unusual_combination": False,
        "low_confidence_warning": confidence < 0.45,
        "dormant_reappeared": False,
        "dormant": True,
        "confidence": confidence,
        "source_refs": sorted(str(ref) for ref in previous.get("source_refs") or [] if ref),
        "bounded_retention_applied": False,
        "dropped_profile_count": 0,
        **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    }
    profile["profile_id"] = str(previous.get("profile_id") or "service-fingerprint-profile-" + _digest({"fingerprint_key": fingerprint_key})[:16])
    return profile


def _profile_confidence(*, rows: list[dict[str, Any]], previous: dict[str, Any] | None, maturity_threshold: int) -> float:
    if not rows:
        return round(max(0.1, float((previous or {}).get("confidence") or 0.2) * 0.5), 3)
    protocols = {str(row.get("protocol") or "unknown") for row in rows}
    ports = {str(row.get("port") or "unknown") for row in rows}
    observed_times = sorted(str(row.get("observed_at") or row.get("generated_at") or "") for row in rows if row.get("observed_at") or row.get("generated_at"))
    timing_consistency = 1.0 if len(observed_times) >= 2 else 0.4
    historical_maturity = min(1.0, (len(rows) + int((previous or {}).get("observation_count") or 0)) / max(1, int(maturity_threshold)))
    observation_density = min(1.0, len(rows) / max(1, int(maturity_threshold)))
    base = score_service_fingerprint_confidence(
        recurrence_count=len(rows),
        timing_consistency=timing_consistency,
        protocol_stability=1.0 if len(protocols) == 1 else 0.45,
        port_consistency=1.0 if len(ports) == 1 else 0.45,
        historical_maturity=historical_maturity,
        observation_density=observation_density,
    )
    average = sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows)
    if any(row.get("unusual_combination") for row in rows):
        base = min(base, 0.72)
    return round(min(1.0, base * 0.7 + average * 0.3), 3)


def _expected_behavior_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "process_names": sorted({str(row.get("process_name") or "unknown") for row in rows}),
        "service_names": sorted({str(row.get("service_name") or "unknown") for row in rows}),
        "protocols": sorted({str(row.get("protocol") or "unknown") for row in rows}),
        "ports": sorted({int(row.get("port")) for row in rows if _is_int(row.get("port"))}),
        "transports": sorted({str(row.get("transport") or "unknown") for row in rows}),
        "flow_roles": sorted({str(row.get("flow_role") or "unknown") for row in rows}),
        "connection_directions": sorted({str(row.get("connection_direction") or "unknown") for row in rows}),
        "runtime_platforms": sorted({str(row.get("runtime_platform") or "unknown") for row in rows}),
        "interface_classes": sorted({str(row.get("interface_class") or "unknown") for row in rows}),
        "metadata_only": True,
        "full_dns_queries_stored": False,
    }


def _group_by_key(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        key = str(row.get("fingerprint_key") or "")
        if key:
            grouped.setdefault(key, []).append(row)
    return dict(sorted(grouped.items()))


def _previous_index(previous_profiles: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in _rows(previous_profiles):
        key = str(row.get("fingerprint_key") or "")
        if key:
            index[key] = row
    return index


def _display_label(rows: list[dict[str, Any]], *, previous: dict[str, Any] | None) -> str:
    for row in rows:
        label = str(row.get("display_label") or "")
        if label:
            return label
    return str((previous or {}).get("display_label") or "unknown-service")


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _is_int(value: Any) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
