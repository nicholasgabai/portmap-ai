from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.destination_learning import (
    DEFAULT_DESTINATION_MATURITY_THRESHOLD,
    DEFAULT_MAX_DESTINATION_BEHAVIOR_RECORDS,
    DESTINATION_LEARNING_RECORD_VERSION,
    DESTINATION_LEARNING_SAFETY_FLAGS,
    DestinationLearningError,
    build_destination_learning_records,
    deterministic_destination_learning_json,
)


DNS_BEHAVIOR_RECORD_VERSION = 1

DNS_BEHAVIOR_SAFETY_FLAGS = {
    **DESTINATION_LEARNING_SAFETY_FLAGS,
    "dns_behavior_learning": True,
}


def build_dns_destination_behavior_report(
    *,
    dns_visibility_report: dict[str, Any] | None = None,
    previous_destinations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_destinations: int = DEFAULT_MAX_DESTINATION_BEHAVIOR_RECORDS,
    maturity_threshold: int = DEFAULT_DESTINATION_MATURITY_THRESHOLD,
    hash_domains: bool = False,
) -> dict[str, Any]:
    timestamp = generated_at or _generated_at(dns_visibility_report)
    destinations = build_destination_learning_records(
        dns_visibility_report=dns_visibility_report,
        previous_destinations=previous_destinations,
        generated_at=timestamp,
        max_records=max_destinations,
        maturity_threshold=maturity_threshold,
        hash_domains=hash_domains,
    )
    profiles = build_dns_behavior_profiles(
        destinations,
        previous_destinations=previous_destinations,
        generated_at=timestamp,
        maturity_threshold=maturity_threshold,
    )
    summary = summarize_dns_destination_behavior(destinations, profiles=profiles, generated_at=timestamp)
    dashboard = build_dns_destination_dashboard_record(summary=summary, profiles=profiles, generated_at=timestamp)
    api = build_dns_destination_api_response(summary=summary, destinations=destinations, profiles=profiles, dashboard=dashboard, generated_at=timestamp)
    export = build_dns_destination_export_record(summary=summary, profiles=profiles, generated_at=timestamp)
    return {
        "record_type": "dns_destination_behavior_report",
        "record_version": DNS_BEHAVIOR_RECORD_VERSION,
        "report_id": "dns-destination-behavior-" + _digest({"generated_at": timestamp, "profiles": [row.get("profile_id") for row in profiles]})[:16],
        "generated_at": timestamp,
        "destinations": destinations,
        "profiles": profiles,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def build_dns_behavior_profiles(
    destinations: Iterable[dict[str, Any]],
    *,
    previous_destinations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    maturity_threshold: int = DEFAULT_DESTINATION_MATURITY_THRESHOLD,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    previous = _previous_index(previous_destinations)
    profiles = [
        _build_profile(destination=row, previous=previous.get(str(row.get("destination_key") or "")), generated_at=timestamp, maturity_threshold=int(maturity_threshold))
        for row in _rows(destinations)
    ]
    return sorted(profiles, key=lambda item: (str(item.get("domain_summary", {}).get("display_domain") or ""), str(item.get("profile_id") or "")))


def classify_dns_destination_behavior(
    *,
    destination: dict[str, Any],
    previous: dict[str, Any] | None = None,
    maturity_threshold: int = DEFAULT_DESTINATION_MATURITY_THRESHOLD,
) -> dict[str, Any]:
    frequency = int(destination.get("destination_frequency") or destination.get("observation_count") or 0)
    previous_seen = bool(previous)
    dormant_returned = bool((previous or {}).get("dormant") or (previous or {}).get("behavior_state") == "dormant") and frequency > 0
    resolver_summary = destination.get("resolver_summary") if isinstance(destination.get("resolver_summary"), dict) else {}
    stable_resolver = bool(resolver_summary.get("stable_resolver"))
    unusual_resolver = int(resolver_summary.get("resolver_count") or 0) > 1 or bool((resolver_summary.get("resolver_type_counts") or {}).get("encrypted"))
    drift = previous_seen and _drift_detected(destination=destination, previous=previous)
    labels: set[str] = set()
    if frequency >= int(maturity_threshold) and stable_resolver and not drift:
        labels.add("stable_destination_behavior")
    if not previous_seen and frequency < int(maturity_threshold):
        labels.add("newly_observed_destination")
    if frequency >= 2:
        labels.add("recurring_destination")
    if unusual_resolver:
        labels.add("unusual_resolver_behavior")
    if dormant_returned:
        labels.add("dormant_destination_returned")
    if drift:
        labels.add("destination_drift_detected")
    if previous_seen and not unusual_resolver and not drift:
        labels.add("baseline_consistent_destination")
    if not labels:
        labels.add("baseline_consistent_destination")
    if frequency == 0 and previous_seen:
        state = "dormant"
    elif "stable_destination_behavior" in labels:
        state = "stable"
    elif "newly_observed_destination" in labels:
        state = "new"
    else:
        state = "recurring"
    return {
        "record_type": "dns_destination_behavior_classification",
        "classification_labels": sorted(labels),
        "behavior_state": state,
        "stable_destination": state == "stable",
        "newly_observed": "newly_observed_destination" in labels,
        "recurring_destination": "recurring_destination" in labels,
        "unusual_resolver_behavior": unusual_resolver,
        "dormant_destination_returned": dormant_returned,
        "destination_drift_detected": drift,
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def summarize_dns_destination_behavior(
    destinations: Iterable[dict[str, Any]],
    *,
    profiles: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    destination_rows = _rows(destinations)
    profile_rows = _rows(profiles)
    return {
        "record_type": "dns_destination_behavior_summary",
        "record_version": DNS_BEHAVIOR_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "destination_count": len(destination_rows),
        "profile_count": len(profile_rows),
        "stable_destination_count": sum(1 for row in profile_rows if row.get("stable_destination")),
        "new_destination_count": sum(1 for row in profile_rows if row.get("newly_observed")),
        "recurring_destination_count": sum(1 for row in profile_rows if row.get("recurring_destination")),
        "unusual_resolver_count": sum(1 for row in profile_rows if row.get("unusual_resolver_behavior")),
        "dormant_return_count": sum(1 for row in profile_rows if row.get("dormant_destination_returned")),
        "drift_count": sum(1 for row in profile_rows if row.get("destination_drift_detected")),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in profile_rows) / len(profile_rows), 3) if profile_rows else 0.0,
        "by_behavior_state": _count_by(profile_rows, "behavior_state"),
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def build_dns_destination_dashboard_record(
    *,
    summary: dict[str, Any],
    profiles: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(profiles)
    review = any(int(summary.get(name) or 0) for name in ("new_destination_count", "unusual_resolver_count", "dormant_return_count", "drift_count"))
    return {
        "record_type": "dns_destination_behavior_dashboard",
        "panel": "dns_destination_behavior",
        "status": "review_required" if review else "ok",
        "generated_at": generated_at or _now(),
        "metrics": {
            "destination_count": int(summary.get("destination_count") or 0),
            "stable_destination_count": int(summary.get("stable_destination_count") or 0),
            "new_destination_count": int(summary.get("new_destination_count") or 0),
            "unusual_resolver_count": int(summary.get("unusual_resolver_count") or 0),
            "dormant_return_count": int(summary.get("dormant_return_count") or 0),
            "drift_count": int(summary.get("drift_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "by_behavior_state": dict(summary.get("by_behavior_state") or {}),
        "rows": [
            {
                "profile_id": row.get("profile_id"),
                "display_domain": (row.get("domain_summary") or {}).get("display_domain") if isinstance(row.get("domain_summary"), dict) else "",
                "behavior_state": row.get("behavior_state"),
                "classification_labels": list(row.get("classification_labels") or []),
                "observation_count": int(row.get("observation_count") or 0),
                "confidence": float(row.get("confidence") or 0.0),
            }
            for row in sorted(rows, key=lambda item: (str(item.get("behavior_state") or ""), str((item.get("domain_summary") or {}).get("display_domain") if isinstance(item.get("domain_summary"), dict) else "")))[:50]
        ],
        "recommended_review": review,
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def build_dns_destination_api_response(
    *,
    summary: dict[str, Any],
    destinations: Iterable[dict[str, Any]],
    profiles: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "dns_destination_behavior_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "destinations": _rows(destinations),
        "profiles": _rows(profiles),
        "dashboard": dict(dashboard),
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def build_dns_destination_export_record(
    *,
    summary: dict[str, Any],
    profiles: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(profiles)
    payload = {
        "record_type": "dns_destination_behavior_export_summary",
        "record_version": DNS_BEHAVIOR_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "profiles": len(rows),
            "stable_destinations": int(summary.get("stable_destination_count") or 0),
            "new_destinations": int(summary.get("new_destination_count") or 0),
            "unusual_resolvers": int(summary.get("unusual_resolver_count") or 0),
            "drift_hints": int(summary.get("drift_count") or 0),
        },
        "profile_ids": [str(row.get("profile_id") or "") for row in rows],
        "digest": "",
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"record_counts": payload["record_counts"], "profile_ids": payload["profile_ids"]})
    return payload


def build_dns_destination_operator_panel(dns_destination_behavior_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not dns_destination_behavior_report:
        return {
            "record_type": "dns_destination_behavior_empty_dashboard_summary",
            "panel": "dns_destination_behavior",
            "status": "empty",
            "generated_at": timestamp,
            "metrics": {},
            "rows": [],
            **DNS_BEHAVIOR_SAFETY_FLAGS,
        }
    dashboard = dns_destination_behavior_report.get("dashboard_status") if isinstance(dns_destination_behavior_report.get("dashboard_status"), dict) else {}
    summary = dns_destination_behavior_report.get("summary") if isinstance(dns_destination_behavior_report.get("summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "dns_destination_behavior_operator_panel",
        "panel": "dns_destination_behavior",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "destination_count": int(metrics.get("destination_count") or summary.get("destination_count") or 0),
            "stable_destination_count": int(metrics.get("stable_destination_count") or summary.get("stable_destination_count") or 0),
            "new_destination_count": int(metrics.get("new_destination_count") or summary.get("new_destination_count") or 0),
            "unusual_resolver_count": int(metrics.get("unusual_resolver_count") or summary.get("unusual_resolver_count") or 0),
            "drift_count": int(metrics.get("drift_count") or summary.get("drift_count") or 0),
            "average_confidence": float(metrics.get("average_confidence") or summary.get("average_confidence") or 0.0),
        },
        "by_behavior_state": dict(summary.get("by_behavior_state") or {}),
        "rows": list(dashboard.get("rows") or []),
        "recommended_review": bool(dashboard.get("recommended_review")),
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }


def deterministic_dns_destination_behavior_json(record: dict[str, Any]) -> str:
    return deterministic_destination_learning_json(record)


def _build_profile(*, destination: dict[str, Any], previous: dict[str, Any] | None, generated_at: str, maturity_threshold: int) -> dict[str, Any]:
    classification = classify_dns_destination_behavior(destination=destination, previous=previous, maturity_threshold=maturity_threshold)
    confidence = _profile_confidence(destination=destination, previous=previous)
    profile = {
        "record_type": "dns_destination_behavior_profile",
        "record_version": DESTINATION_LEARNING_RECORD_VERSION,
        "generated_at": generated_at,
        "destination_key": str(destination.get("destination_key") or ""),
        "domain_summary": dict(destination.get("domain_summary") or {}),
        "first_seen": str(destination.get("first_seen") or ""),
        "last_seen": str(destination.get("last_seen") or ""),
        "observation_count": int(destination.get("destination_frequency") or 0),
        "recurrence_timing": dict(destination.get("recurrence_timing") or {}),
        "resolver_summary": dict(destination.get("resolver_summary") or {}),
        "rolling_novelty_score": float(destination.get("rolling_novelty_score") or 0.0),
        "confidence": confidence,
        "source_refs": sorted(str(ref) for ref in destination.get("source_refs") or [] if ref),
        **classification,
        **DNS_BEHAVIOR_SAFETY_FLAGS,
    }
    profile["profile_id"] = "dns-destination-profile-" + _digest({"destination_key": profile["destination_key"]})[:16]
    return profile


def _profile_confidence(*, destination: dict[str, Any], previous: dict[str, Any] | None) -> float:
    confidence = float(destination.get("baseline_confidence") or 0.0)
    if previous:
        confidence = min(1.0, confidence + 0.08)
    if int(destination.get("anomaly_overlap_count") or 0):
        confidence = max(0.05, confidence - 0.08)
    return round(confidence, 3)


def _drift_detected(*, destination: dict[str, Any], previous: dict[str, Any] | None) -> bool:
    if not previous:
        return False
    current_resolvers = set((destination.get("resolver_summary") or {}).get("resolver_hashes") or [])
    previous_resolvers = set((previous.get("resolver_summary") or {}).get("resolver_hashes") or [])
    if current_resolvers and previous_resolvers and current_resolvers != previous_resolvers:
        return True
    current_transport = dict(destination.get("transport_protocol_associations") or {})
    previous_transport = dict(previous.get("transport_protocol_associations") or {})
    return bool(current_transport and previous_transport and current_transport != previous_transport)


def _previous_index(previous_destinations: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index = {}
    for row in _rows(previous_destinations):
        key = str(row.get("destination_key") or "")
        if key:
            index[key] = row
    return index


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _generated_at(record: dict[str, Any] | None) -> str:
    if isinstance(record, dict) and record.get("generated_at"):
        return str(record["generated_at"])
    return _now()


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
