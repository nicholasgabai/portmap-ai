from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.dns_visibility import sanitize_domain_name
from core_engine.telemetry.fingerprint_profiles import (
    DEFAULT_MAX_SERVICE_FINGERPRINT_PROFILES,
    DEFAULT_SERVICE_FINGERPRINT_MATURITY_THRESHOLD,
    SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    build_fingerprint_profile_records,
    build_service_fingerprint_api_response,
    build_service_fingerprint_dashboard_record,
    build_service_fingerprint_export_record,
    summarize_service_fingerprint_profiles,
)
from core_engine.telemetry.flows import SERVICE_PORTS


SERVICE_BEHAVIOR_FINGERPRINT_RECORD_VERSION = 1
DEFAULT_MAX_SERVICE_BEHAVIOR_FINGERPRINTS = 1000

SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS = {
    **SERVICE_FINGERPRINT_PROFILE_SAFETY_FLAGS,
    "packet_payloads_stored": False,
    "packet_capture_stored": False,
    "credentials_stored": False,
    "full_dns_queries_stored": False,
    "command_line_arguments_stored": False,
    "user_documents_collected": False,
    "remote_learning": False,
}


class ServiceBehaviorFingerprintError(ValueError):
    """Raised when service behavior fingerprint input is malformed."""


def build_service_behavior_fingerprint_report(
    *,
    service_attributions: Iterable[dict[str, Any]] | None = None,
    flow_observations: Iterable[dict[str, Any]] | None = None,
    dns_records: Iterable[dict[str, Any]] | None = None,
    previous_profiles: Iterable[dict[str, Any]] | None = None,
    runtime_platform: str = "unknown",
    interface_class: str = "unknown",
    generated_at: str | None = None,
    max_fingerprints: int = DEFAULT_MAX_SERVICE_BEHAVIOR_FINGERPRINTS,
    max_profiles: int = DEFAULT_MAX_SERVICE_FINGERPRINT_PROFILES,
    maturity_threshold: int = DEFAULT_SERVICE_FINGERPRINT_MATURITY_THRESHOLD,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if int(max_fingerprints) <= 0:
        raise ServiceBehaviorFingerprintError("max_fingerprints must be positive")
    rows = build_service_fingerprint_records(
        service_attributions=service_attributions,
        flow_observations=flow_observations,
        dns_records=dns_records,
        runtime_platform=runtime_platform,
        interface_class=interface_class,
        generated_at=timestamp,
    )
    dropped = max(0, len(rows) - int(max_fingerprints))
    selected = sorted(rows, key=lambda item: (str(item.get("display_label") or ""), str(item.get("fingerprint_id") or "")))[: int(max_fingerprints)]
    for row in selected:
        row["bounded_retention_applied"] = dropped > 0
        row["dropped_fingerprint_count"] = dropped
    profiles = build_fingerprint_profile_records(
        selected,
        previous_profiles=previous_profiles,
        generated_at=timestamp,
        max_profiles=max_profiles,
        maturity_threshold=maturity_threshold,
    )
    summary = summarize_service_fingerprints(selected, profiles=profiles, dropped_fingerprint_count=dropped, generated_at=timestamp)
    profile_summary = summarize_service_fingerprint_profiles(profiles, generated_at=timestamp)
    dashboard = build_service_fingerprint_dashboard_record(summary=profile_summary, profiles=profiles, generated_at=timestamp)
    api = build_service_fingerprint_api_response(summary=profile_summary, profiles=profiles, dashboard=dashboard, generated_at=timestamp)
    export = build_service_fingerprint_export_record(summary=profile_summary, profiles=profiles, generated_at=timestamp)
    return {
        "record_type": "service_behavior_fingerprint_report",
        "record_version": SERVICE_BEHAVIOR_FINGERPRINT_RECORD_VERSION,
        "report_id": "service-behavior-fingerprint-report-" + _digest({"generated_at": timestamp, "fingerprints": [row.get("fingerprint_id") for row in selected]})[:16],
        "generated_at": timestamp,
        "max_fingerprints": int(max_fingerprints),
        "dropped_fingerprint_count": dropped,
        "fingerprints": selected,
        "profiles": profiles,
        "summary": summary,
        "profile_summary": profile_summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }


def build_service_fingerprint_records(
    *,
    service_attributions: Iterable[dict[str, Any]] | None = None,
    flow_observations: Iterable[dict[str, Any]] | None = None,
    dns_records: Iterable[dict[str, Any]] | None = None,
    runtime_platform: str = "unknown",
    interface_class: str = "unknown",
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    flow_index = _flow_index(flow_observations)
    dns_summary = _dns_association_summary(dns_records)
    fingerprints = []
    for row in _rows(service_attributions):
        fingerprints.append(
            build_service_fingerprint_record(
                service_attribution=row,
                flow_observation=flow_index.get(str(row.get("flow_ref") or "")),
                dns_association_summary=dns_summary,
                runtime_platform=runtime_platform,
                interface_class=interface_class,
                generated_at=timestamp,
            )
        )
    if not fingerprints:
        for row in _rows(flow_observations):
            fingerprints.append(
                build_service_fingerprint_record(
                    service_attribution={},
                    flow_observation=row,
                    dns_association_summary=dns_summary,
                    runtime_platform=runtime_platform,
                    interface_class=interface_class,
                    generated_at=timestamp,
                )
            )
    return [row for row in fingerprints if row.get("fingerprint_key")]


def build_service_fingerprint_record(
    *,
    service_attribution: dict[str, Any] | None = None,
    flow_observation: dict[str, Any] | None = None,
    dns_association_summary: dict[str, Any] | None = None,
    runtime_platform: str = "unknown",
    interface_class: str = "unknown",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    attribution = dict(service_attribution or {})
    flow = dict(flow_observation or {})
    service_hint = flow.get("service_port_hint") if isinstance(flow.get("service_port_hint"), dict) else {}
    process = attribution.get("process_attribution") if isinstance(attribution.get("process_attribution"), dict) else {}
    process_display = process.get("process_display") if isinstance(process.get("process_display"), dict) else {}
    direction = flow.get("direction") if isinstance(flow.get("direction"), dict) else {}
    service_name = _safe_label(attribution.get("service_name") or service_hint.get("service_name") or "unknown")
    port = _safe_int(attribution.get("service_port") or service_hint.get("service_port") or attribution.get("port"))
    protocol = _safe_label(attribution.get("protocol_hint") or attribution.get("protocol") or service_name)
    transport = _safe_label(attribution.get("transport_protocol") or flow.get("transport_protocol") or "unknown")
    process_hint = ""
    if isinstance(attribution.get("process"), dict):
        process_hint = str((attribution.get("process") or {}).get("process_name") or "")
    process_name = _safe_process_name(
        process_display.get("display_name")
        or process_display.get("process_name")
        or attribution.get("process_name")
        or process_hint
    )
    if not process_name:
        process_name = "unknown"
    connection_direction = _safe_label(direction.get("direction") or attribution.get("connection_direction") or "unknown")
    flow_role = _flow_role(service_endpoint=str(service_hint.get("service_endpoint") or ""), connection_direction=connection_direction)
    labels = classify_service_fingerprint(
        process_name=process_name,
        service_name=service_name,
        protocol=protocol,
        port=port,
        transport=transport,
    )
    confidence = score_service_fingerprint_record(
        service_confidence=float(attribution.get("confidence") or service_hint.get("confidence") or 0.0),
        process_status=str(process.get("status") or "unknown"),
        protocol=protocol,
        port=port,
        classification_labels=labels,
    )
    key_payload = {
        "process_name": process_name,
        "service_name": service_name,
        "protocol": protocol,
        "port": port,
        "transport": transport,
        "flow_role": flow_role,
        "runtime_platform": _safe_label(runtime_platform),
        "interface_class": _safe_label(interface_class),
        "connection_direction": connection_direction,
    }
    fingerprint_key = _digest(key_payload)[:32]
    source_refs = sorted({str(ref) for ref in _as_list(attribution.get("source_refs")) + _as_list(flow.get("source_refs")) if ref})
    observed_at = str(attribution.get("last_seen") or attribution.get("observed_at") or flow.get("last_seen") or flow.get("generated_at") or timestamp)
    record = {
        "record_type": "service_behavior_fingerprint",
        "record_version": SERVICE_BEHAVIOR_FINGERPRINT_RECORD_VERSION,
        "generated_at": timestamp,
        "observed_at": observed_at,
        "fingerprint_key": fingerprint_key,
        "display_label": _display_label(service_name=service_name, protocol=protocol, port=port, process_name=process_name),
        "process_name": process_name,
        "service_name": service_name,
        "protocol": protocol,
        "port": port,
        "transport": transport,
        "flow_role": flow_role,
        "dns_association_summary": dict(dns_association_summary or _empty_dns_summary()),
        "runtime_platform": _safe_label(runtime_platform),
        "interface_class": _safe_label(interface_class),
        "connection_direction": connection_direction,
        "classification_labels": labels,
        "unusual_combination": any(label in labels for label in {"uncommon_protocol_binding", "unusual_process_port_pair"}),
        "confidence": confidence,
        "confidence_level": _confidence_level(confidence),
        "source_refs": source_refs,
        "flow_ref": str(attribution.get("flow_ref") or flow.get("flow_ref") or ""),
        "bounded_retention_applied": False,
        "dropped_fingerprint_count": 0,
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }
    record["fingerprint_id"] = "service-behavior-fingerprint-" + _digest({"fingerprint_key": fingerprint_key, "observed_at": observed_at, "flow_ref": record["flow_ref"]})[:16]
    return record


def classify_service_fingerprint(
    *,
    process_name: str,
    service_name: str,
    protocol: str,
    port: int | None,
    transport: str,
) -> list[str]:
    labels: set[str] = set()
    expected_service = SERVICE_PORTS.get(port) if port is not None else None
    service = _safe_label(service_name)
    proto = _safe_label(protocol)
    proc = _safe_label(process_name)
    if expected_service and service not in {"unknown", expected_service}:
        labels.add("uncommon_protocol_binding")
    if proto in {"http", "https", "tls"} and port in {22, 53}:
        labels.add("uncommon_protocol_binding")
    if proto in {"ssh"} and port not in {22, 2222}:
        labels.add("uncommon_protocol_binding")
    if _process_port_unusual(process_name=proc, service_name=service, port=port):
        labels.add("unusual_process_port_pair")
    if transport not in {"tcp", "udp", "icmp", "unknown"}:
        labels.add("uncommon_protocol_binding")
    if not labels:
        labels.add("baseline_consistent")
    return sorted(labels)


def score_service_fingerprint_record(
    *,
    service_confidence: float,
    process_status: str,
    protocol: str,
    port: int | None,
    classification_labels: Iterable[str],
) -> float:
    labels = set(classification_labels or [])
    score = 0.35
    score += min(0.25, max(0.0, float(service_confidence)) * 0.25)
    if str(process_status) == "matched":
        score += 0.2
    elif str(process_status) in {"unsupported", "permission_denied"}:
        score -= 0.1
    if _safe_label(protocol) != "unknown":
        score += 0.1
    if port is not None:
        score += 0.1
    if labels & {"uncommon_protocol_binding", "unusual_process_port_pair"}:
        score -= 0.18
    return round(max(0.05, min(1.0, score)), 3)


def summarize_service_fingerprints(
    fingerprints: Iterable[dict[str, Any]],
    *,
    profiles: Iterable[dict[str, Any]],
    dropped_fingerprint_count: int = 0,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(fingerprints)
    profile_rows = _rows(profiles)
    return {
        "record_type": "service_behavior_fingerprint_summary",
        "record_version": SERVICE_BEHAVIOR_FINGERPRINT_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "fingerprint_count": len(rows),
        "profile_count": len(profile_rows),
        "dropped_fingerprint_count": int(dropped_fingerprint_count),
        "unusual_combination_count": sum(1 for row in rows if row.get("unusual_combination")),
        "low_confidence_count": sum(1 for row in rows if float(row.get("confidence") or 0.0) < 0.45),
        "stable_profile_count": sum(1 for row in profile_rows if row.get("stable_service_profile")),
        "dormant_reappeared_count": sum(1 for row in profile_rows if row.get("dormant_reappeared")),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_service": _count_by(rows, "service_name"),
        "by_protocol": _count_by(rows, "protocol"),
        "by_runtime_platform": _count_by(rows, "runtime_platform"),
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }


def build_service_fingerprint_operator_panel(service_fingerprint_report: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not service_fingerprint_report:
        return {
            "record_type": "service_fingerprints_empty_dashboard_summary",
            "panel": "service_fingerprints",
            "status": "empty",
            "generated_at": timestamp,
            "metrics": {},
            "rows": [],
            **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
        }
    dashboard = service_fingerprint_report.get("dashboard_status") if isinstance(service_fingerprint_report.get("dashboard_status"), dict) else {}
    summary = service_fingerprint_report.get("summary") if isinstance(service_fingerprint_report.get("summary"), dict) else {}
    profile_summary = service_fingerprint_report.get("profile_summary") if isinstance(service_fingerprint_report.get("profile_summary"), dict) else {}
    metrics = dashboard.get("metrics") if isinstance(dashboard.get("metrics"), dict) else {}
    return {
        "record_type": "service_fingerprint_operator_panel",
        "panel": "service_fingerprints",
        "status": str(dashboard.get("status") or "ok"),
        "generated_at": timestamp,
        "metrics": {
            "fingerprint_count": int(summary.get("fingerprint_count") or 0),
            "profile_count": int(metrics.get("profile_count") or profile_summary.get("profile_count") or 0),
            "stable_profile_count": int(metrics.get("stable_profile_count") or profile_summary.get("stable_profile_count") or 0),
            "unusual_combination_count": int(metrics.get("unusual_combination_count") or profile_summary.get("unusual_combination_count") or 0),
            "dormant_reappeared_count": int(metrics.get("dormant_reappeared_count") or profile_summary.get("dormant_reappeared_count") or 0),
            "average_confidence": float(metrics.get("average_confidence") or profile_summary.get("average_confidence") or 0.0),
        },
        "by_behavior_state": dict(profile_summary.get("by_behavior_state") or {}),
        "rows": list(dashboard.get("rows") or []),
        "recommended_review": bool(dashboard.get("recommended_review")),
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }


def deterministic_service_behavior_fingerprint_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _flow_index(flow_observations: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index = {}
    for row in _rows(flow_observations):
        ref = str(row.get("flow_ref") or "")
        if ref:
            index[ref] = row
    return index


def _dns_association_summary(dns_records: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    domains = []
    for row in _rows(dns_records):
        value = str(row.get("safe_domain") or row.get("domain") or row.get("query_name") or row.get("name") or "")
        if not value:
            continue
        safe_domain, _governance = sanitize_domain_name(value)
        if safe_domain:
            domains.append(_redacted_domain_summary(safe_domain))
    domains = sorted(set(domains))[:10]
    return {
        "record_type": "service_fingerprint_dns_association_summary",
        "domain_summary_count": len(domains),
        "redacted_domain_summaries": domains,
        "full_dns_queries_stored": False,
        "dns_query_contents_stored": False,
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }


def _empty_dns_summary() -> dict[str, Any]:
    return {
        "record_type": "service_fingerprint_dns_association_summary",
        "domain_summary_count": 0,
        "redacted_domain_summaries": [],
        "full_dns_queries_stored": False,
        "dns_query_contents_stored": False,
        **SERVICE_BEHAVIOR_FINGERPRINT_SAFETY_FLAGS,
    }


def _redacted_domain_summary(domain: str) -> str:
    parts = [part for part in str(domain).split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    return "<redacted>." + ".".join(parts[-2:])


def _flow_role(*, service_endpoint: str, connection_direction: str) -> str:
    endpoint = _safe_label(service_endpoint)
    if endpoint in {"initiator", "responder"}:
        return "server" if endpoint == "responder" else "client"
    direction = _safe_label(connection_direction)
    if direction == "inbound":
        return "server"
    if direction == "outbound":
        return "client"
    return "unknown"


def _process_port_unusual(*, process_name: str, service_name: str, port: int | None) -> bool:
    proc = _safe_label(process_name)
    service = _safe_label(service_name)
    if port == 22 and any(token in proc for token in ("web", "http", "browser")):
        return True
    if port in {80, 443} and any(token in proc for token in ("ssh", "shell", "terminal")):
        return True
    if service in {"ssh"} and any(token in proc for token in ("web", "http", "browser")):
        return True
    if service in {"http", "https"} and any(token in proc for token in ("ssh", "shell", "terminal")):
        return True
    return False


def _display_label(*, service_name: str, protocol: str, port: int | None, process_name: str) -> str:
    return f"{service_name or 'unknown'}/{protocol or 'unknown'}/{port if port is not None else 'unknown'}/{process_name or 'unknown'}"


def _safe_process_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if any(token in text for token in ("token", "secret", "password", "credential", "key")):
        return "redacted-process"
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in text)[:64]


def _safe_label(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    if not text:
        return "unknown"
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in text)[:64]


def _safe_int(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _confidence_level(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
