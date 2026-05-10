from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Iterable

from ai_agent.baseline_store import empty_baseline, normalize_baseline, normalize_device_profile


MIN_PROFILE_EVENTS = 3
SEVERITY_SCORES = {"info": 0.1, "low": 0.25, "medium": 0.55, "high": 0.8}


def normalize_observation(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("behavior observation must be an object")
    metadata = _metadata(event)
    initiator = event.get("initiator") if isinstance(event.get("initiator"), dict) else {}
    responder = event.get("responder") if isinstance(event.get("responder"), dict) else {}
    device_id = str(
        event.get("device_id")
        or event.get("node_id")
        or metadata.get("device_id")
        or metadata.get("node_id")
        or initiator.get("ip")
        or metadata.get("src_ip")
        or "unknown"
    )
    peer = str(responder.get("ip") or metadata.get("dst_ip") or event.get("peer") or "")
    port = _optional_int(responder.get("port") or metadata.get("dst_port") or event.get("port"))
    transports = event.get("transports")
    transport = str(
        metadata.get("protocol")
        or metadata.get("transport")
        or event.get("transport")
        or (transports[0] if isinstance(transports, list) and transports else None)
        or "unknown"
    ).upper()
    application = _application(event, metadata)
    timestamp = _timestamp(event, metadata)
    hour = datetime.fromtimestamp(timestamp, tz=UTC).hour if timestamp > 0 else None
    payload_bytes = _int(event.get("payload_bytes") or metadata.get("payload_bytes"))
    return {
        "device_id": device_id,
        "peer": peer,
        "port": port,
        "transport": transport,
        "application": application,
        "timestamp": timestamp,
        "hour": hour,
        "payload_bytes": payload_bytes,
        "source": str(event.get("source") or "observation"),
    }


def update_baseline(
    baseline: dict[str, Any] | None,
    observations: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    updated = normalize_baseline(deepcopy(baseline) if baseline else empty_baseline())
    for raw in observations:
        observation = normalize_observation(raw)
        profile = updated["devices"].setdefault(observation["device_id"], normalize_device_profile())
        _update_profile(profile, observation)
    updated["updated_at"] = datetime.now(UTC).isoformat()
    return updated


def analyze_behavior(
    event: dict[str, Any],
    baseline: dict[str, Any] | None,
    *,
    min_profile_events: int = MIN_PROFILE_EVENTS,
) -> dict[str, Any]:
    observation = normalize_observation(event)
    normalized_baseline = normalize_baseline(baseline)
    profile = normalized_baseline["devices"].get(observation["device_id"])
    findings: list[dict[str, Any]] = []

    if not profile:
        findings.append(_finding("new_device", "medium", "device_id", "device has no learned behavior baseline"))
    else:
        event_count = int(profile.get("event_count") or 0)
        if event_count < min_profile_events:
            findings.append(_finding("low_confidence_baseline", "low", "event_count", "device baseline has limited observations"))
        _check_counted_dimension(findings, "new_destination_port", "port", observation["port"], profile.get("ports"), event_count)
        _check_counted_dimension(findings, "new_peer", "peer", observation["peer"], profile.get("peers"), event_count)
        _check_counted_dimension(findings, "new_application_protocol", "application", observation["application"], profile.get("applications"), event_count)
        _check_counted_dimension(findings, "unusual_hour", "hour", observation["hour"], profile.get("hour_buckets"), event_count, rare_threshold=0.15)

    score = _score_findings(findings)
    return {
        "device_id": observation["device_id"],
        "observation": observation,
        "status": "anomalous" if score >= 0.55 else "normal" if findings == [] else "review",
        "score": score,
        "findings": findings,
        "baseline_event_count": int((profile or {}).get("event_count") or 0),
        "model": "local_behavior_baseline",
        "raw_payload_stored": False,
    }


def analyze_events(
    events: Iterable[dict[str, Any]],
    baseline: dict[str, Any] | None,
    *,
    learn: bool = False,
) -> dict[str, Any]:
    baseline_before = normalize_baseline(baseline)
    analyses = [analyze_behavior(event, baseline_before) for event in events]
    result: dict[str, Any] = {
        "ok": True,
        "analysis_count": len(analyses),
        "analyses": analyses,
        "baseline_updated": False,
        "baseline": baseline_before,
    }
    if learn:
        result["baseline"] = update_baseline(baseline_before, events)
        result["baseline_updated"] = True
    return result


def summarize_device_profile(device_id: str, baseline: dict[str, Any] | None) -> dict[str, Any]:
    profile = normalize_baseline(baseline)["devices"].get(str(device_id), normalize_device_profile())
    return {
        "device_id": str(device_id),
        "event_count": int(profile.get("event_count") or 0),
        "top_ports": _top_counts(profile.get("ports")),
        "top_peers": _top_counts(profile.get("peers")),
        "top_applications": _top_counts(profile.get("applications")),
        "active_hours": _top_counts(profile.get("hour_buckets")),
    }


def _metadata(event: dict[str, Any]) -> dict[str, Any]:
    metadata = dict(event.get("metadata") or {})
    headers = event.get("headers") or {}
    if isinstance(headers, dict) and isinstance(headers.get("network"), dict):
        metadata.update({key: value for key, value in headers["network"].items() if value not in {None, ""}})
    return metadata


def _application(event: dict[str, Any], metadata: dict[str, Any]) -> str:
    applications = event.get("application_protocols")
    if isinstance(applications, list) and applications:
        return str(applications[0]).upper()
    values = [
        event.get("application"),
        event.get("application_protocol"),
        (event.get("dissection") or {}).get("protocol") if isinstance(event.get("dissection"), dict) else None,
        (event.get("dpi") or {}).get("protocol") if isinstance(event.get("dpi"), dict) else None,
        metadata.get("application_protocol"),
    ]
    for value in values:
        if value:
            return str(value).upper()
    return "unknown"


def _timestamp(event: dict[str, Any], metadata: dict[str, Any]) -> float:
    value = event.get("timestamp") or metadata.get("timestamp") or 0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _update_profile(profile: dict[str, Any], observation: dict[str, Any]) -> None:
    profile["event_count"] = int(profile.get("event_count") or 0) + 1
    timestamp = observation.get("timestamp") or 0
    if timestamp:
        profile["first_seen"] = min(float(profile.get("first_seen") or timestamp), float(timestamp))
        profile["last_seen"] = max(float(profile.get("last_seen") or timestamp), float(timestamp))
    for key, value in {
        "ports": observation.get("port"),
        "peers": observation.get("peer"),
        "applications": observation.get("application"),
        "transports": observation.get("transport"),
        "hour_buckets": observation.get("hour"),
    }.items():
        if value in {None, ""}:
            continue
        _increment(profile.setdefault(key, {}), str(value))


def _check_counted_dimension(
    findings: list[dict[str, Any]],
    finding_type: str,
    evidence: str,
    value: Any,
    counts: Any,
    event_count: int,
    *,
    rare_threshold: float = 0.1,
) -> None:
    if value in {None, "", "unknown"}:
        return
    count_map = counts if isinstance(counts, dict) else {}
    count = int(count_map.get(str(value), 0) or 0)
    if count == 0:
        findings.append(_finding(finding_type, "medium", evidence, f"{value} has not appeared in the learned baseline"))
        return
    if event_count > 0 and count / event_count < rare_threshold:
        findings.append(_finding(f"rare_{evidence}", "low", evidence, f"{value} is uncommon for this device"))


def _finding(finding_type: str, severity: str, evidence: str, detail: str) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "evidence": evidence,
        "detail": detail,
    }


def _score_findings(findings: list[dict[str, Any]]) -> float:
    score = 0.1
    for finding in findings:
        score = max(score, SEVERITY_SCORES.get(str(finding.get("severity") or "info"), 0.1))
    return round(score, 2)


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = int(counts.get(key, 0) or 0) + 1


def _top_counts(counts: Any, limit: int = 5) -> list[dict[str, Any]]:
    if not isinstance(counts, dict):
        return []
    rows = [{"value": str(key), "count": int(value)} for key, value in counts.items()]
    return sorted(rows, key=lambda item: (-item["count"], item["value"]))[:limit]


def _optional_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0
