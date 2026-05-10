from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from typing import Any, Iterable


DEFAULT_WINDOW_SECONDS = 300.0
SEVERITY_SCORES = {"info": 0.1, "low": 0.3, "medium": 0.6, "high": 0.85, "critical": 0.95}
SCAN_PORT_THRESHOLD = 5
SCAN_PEER_THRESHOLD = 5


def correlate_events(
    events: Iterable[dict[str, Any]],
    *,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
) -> dict[str, Any]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")
    normalized = [event for event in (normalize_event(item) for item in events) if event is not None]
    incidents: list[dict[str, Any]] = []
    incidents.extend(_repeated_anomalies(normalized, window_seconds=window_seconds))
    incidents.extend(_suspicious_scans(normalized, window_seconds=window_seconds))
    incidents.extend(_lateral_movement(normalized, window_seconds=window_seconds))
    incidents.extend(_payload_behavior_chains(normalized, window_seconds=window_seconds))
    incidents = _dedupe_incidents(incidents)
    return {
        "ok": True,
        "event_count": len(normalized),
        "incident_count": len(incidents),
        "incidents": sorted(incidents, key=lambda item: (-item["score"], item["type"], item["entity"])),
        "risk_score": max([incident["score"] for incident in incidents], default=0.1),
        "window_seconds": float(window_seconds),
        "raw_payload_stored": False,
        "model": "local_threat_correlation",
    }


def normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None
    kind = _event_kind(event)
    timestamp = _timestamp(event)
    entity = _entity(event)
    peer = _peer(event)
    port = _port(event)
    finding_types = _finding_types(event)
    score = _score(event, finding_types)
    severity = _severity(score, finding_types)
    normalized = {
        "kind": kind,
        "timestamp": timestamp,
        "entity": entity,
        "peer": peer,
        "port": port,
        "protocol": _protocol(event),
        "score": score,
        "severity": severity,
        "findings": finding_types,
        "event_id": _event_id(event, kind, timestamp, entity, peer, port, finding_types),
        "source": str(event.get("model") or event.get("source") or kind),
        "summary": _summary(event, finding_types),
    }
    return normalized


def _repeated_anomalies(events: list[dict[str, Any]], *, window_seconds: float) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["score"] >= 0.55 or event["severity"] in {"medium", "high", "critical"}:
            by_entity[event["entity"]].append(event)
    for entity, rows in by_entity.items():
        for cluster in _window_clusters(rows, window_seconds):
            if len(cluster) < 3:
                continue
            incidents.append(_incident(
                "repeated_anomaly",
                "high" if len(cluster) >= 5 else "medium",
                entity,
                cluster,
                "repeated anomalous events observed for the same entity",
            ))
    return incidents


def _suspicious_scans(events: list[dict[str, Any]], *, window_seconds: float) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["port"] is not None or "new_destination_port" in event["findings"]:
            by_entity[event["entity"]].append(event)
    for entity, rows in by_entity.items():
        for cluster in _window_clusters(rows, window_seconds):
            ports = {event["port"] for event in cluster if event["port"] is not None}
            peers = {event["peer"] for event in cluster if event["peer"]}
            if len(ports) >= SCAN_PORT_THRESHOLD or len(peers) >= SCAN_PEER_THRESHOLD:
                incidents.append(_incident(
                    "suspicious_scan_behavior",
                    "high" if len(ports) >= SCAN_PORT_THRESHOLD * 2 else "medium",
                    entity,
                    cluster,
                    "many destination ports or peers were contacted in a short window",
                ))
    return incidents


def _lateral_movement(events: list[dict[str, Any]], *, window_seconds: float) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    candidates = [
        event
        for event in events
        if event["port"] in {22, 3389, 445, 5985, 5986}
        or {"new_peer", "new_destination_port", "new_application_protocol"} & set(event["findings"])
    ]
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in candidates:
        by_entity[event["entity"]].append(event)
    for entity, rows in by_entity.items():
        for cluster in _window_clusters(rows, window_seconds):
            peers = {event["peer"] for event in cluster if event["peer"]}
            ports = {event["port"] for event in cluster if event["port"] in {22, 3389, 445, 5985, 5986}}
            if len(peers) >= 2 and ports:
                incidents.append(_incident(
                    "lateral_movement_indicator",
                    "high",
                    entity,
                    cluster,
                    "administrative or file-sharing access patterns reached multiple peers",
                ))
    return incidents


def _payload_behavior_chains(events: list[dict[str, Any]], *, window_seconds: float) -> list[dict[str, Any]]:
    incidents: list[dict[str, Any]] = []
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["kind"] in {"payload", "behavior"} or event["findings"]:
            by_entity[event["entity"]].append(event)
    for entity, rows in by_entity.items():
        for cluster in _window_clusters(rows, window_seconds):
            findings = {finding for event in cluster for finding in event["findings"]}
            has_payload = bool(findings & {
                "credential_marker",
                "cleartext_sensitive_payload",
                "possible_exfiltration_payload",
                "possible_exfiltration_volume",
                "beaconing_candidate",
                "command_marker",
            })
            has_behavior = bool(findings & {
                "new_device",
                "new_peer",
                "new_destination_port",
                "new_application_protocol",
                "unusual_hour",
            })
            if has_payload and has_behavior:
                incidents.append(_incident(
                    "chained_behavior_payload_risk",
                    "high",
                    entity,
                    cluster,
                    "payload and behavior anomalies appeared in the same correlation window",
                ))
    return incidents


def _window_clusters(rows: list[dict[str, Any]], window_seconds: float) -> list[list[dict[str, Any]]]:
    sorted_rows = sorted(rows, key=lambda item: item["timestamp"])
    clusters: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for row in sorted_rows:
        if not current:
            current = [row]
            continue
        if row["timestamp"] and current[-1]["timestamp"] and row["timestamp"] - current[-1]["timestamp"] <= window_seconds:
            current.append(row)
        else:
            clusters.append(current)
            current = [row]
    if current:
        clusters.append(current)
    return clusters


def _incident(
    incident_type: str,
    severity: str,
    entity: str,
    events: list[dict[str, Any]],
    explanation: str,
) -> dict[str, Any]:
    findings = sorted({finding for event in events for finding in event["findings"]})
    peers = sorted({event["peer"] for event in events if event["peer"]})
    ports = sorted({event["port"] for event in events if event["port"] is not None})
    score = max([SEVERITY_SCORES.get(severity, 0.1), *[event["score"] for event in events]], default=0.1)
    event_ids = [event["event_id"] for event in events]
    return {
        "incident_id": sha256(f"{incident_type}:{entity}:{','.join(event_ids)}".encode("utf-8")).hexdigest()[:16],
        "type": incident_type,
        "severity": severity,
        "score": round(score, 2),
        "entity": entity,
        "event_count": len(events),
        "first_seen": min(event["timestamp"] for event in events),
        "last_seen": max(event["timestamp"] for event in events),
        "peers": peers,
        "ports": ports,
        "findings": findings,
        "event_ids": event_ids,
        "explanation": explanation,
        "supporting_evidence": [
            {
                "event_id": event["event_id"],
                "kind": event["kind"],
                "score": event["score"],
                "severity": event["severity"],
                "summary": event["summary"],
            }
            for event in events[:10]
        ],
    }


def _dedupe_incidents(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for incident in incidents:
        if incident["incident_id"] in seen:
            continue
        seen.add(incident["incident_id"])
        deduped.append(incident)
    return deduped


def _event_kind(event: dict[str, Any]) -> str:
    model = str(event.get("model") or "")
    if model == "local_payload_classifier" or "label" in event:
        return "payload"
    if model == "local_behavior_baseline" or "baseline_event_count" in event:
        return "behavior"
    if "flow_id" in event or "flow_key" in event:
        return "flow"
    if "probable_os" in event:
        return "os"
    if "service" in event:
        return "service"
    return str(event.get("event_type") or event.get("type") or "event")


def _entity(event: dict[str, Any]) -> str:
    observation = event.get("observation") if isinstance(event.get("observation"), dict) else {}
    network = _network(event)
    initiator = event.get("initiator") if isinstance(event.get("initiator"), dict) else {}
    return str(
        event.get("device_id")
        or event.get("node_id")
        or observation.get("device_id")
        or initiator.get("ip")
        or network.get("src_ip")
        or event.get("target")
        or "unknown"
    )


def _peer(event: dict[str, Any]) -> str:
    observation = event.get("observation") if isinstance(event.get("observation"), dict) else {}
    network = _network(event)
    responder = event.get("responder") if isinstance(event.get("responder"), dict) else {}
    return str(
        observation.get("peer")
        or responder.get("ip")
        or network.get("dst_ip")
        or event.get("peer")
        or ""
    )


def _port(event: dict[str, Any]) -> int | None:
    observation = event.get("observation") if isinstance(event.get("observation"), dict) else {}
    responder = event.get("responder") if isinstance(event.get("responder"), dict) else {}
    network = _network(event)
    for value in (observation.get("port"), responder.get("port"), network.get("dst_port"), event.get("port")):
        try:
            if value not in {None, ""}:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _protocol(event: dict[str, Any]) -> str:
    observation = event.get("observation") if isinstance(event.get("observation"), dict) else {}
    for value in (
        event.get("protocol"),
        event.get("application_protocol"),
        observation.get("application"),
        (event.get("dissection") or {}).get("protocol") if isinstance(event.get("dissection"), dict) else None,
    ):
        if value:
            return str(value).upper()
    return "unknown"


def _finding_types(event: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    for source in (event.get("findings"), event.get("aggregate_findings")):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and item.get("type"):
                findings.append(str(item["type"]))
            elif item:
                findings.append(str(item))
    return sorted(set(findings))


def _score(event: dict[str, Any], findings: list[str]) -> float:
    for key in ("score", "risk_score", "confidence"):
        try:
            if event.get(key) is not None:
                return round(max(0.0, min(1.0, float(event[key]))), 2)
        except (TypeError, ValueError):
            pass
    return 0.55 if findings else 0.1


def _severity(score: float, findings: list[str]) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    if findings:
        return "low"
    return "info"


def _timestamp(event: dict[str, Any]) -> float:
    observation = event.get("observation") if isinstance(event.get("observation"), dict) else {}
    network = _network(event)
    for value in (event.get("timestamp"), observation.get("timestamp"), network.get("timestamp"), event.get("first_seen")):
        try:
            if value not in {None, ""}:
                return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def _network(event: dict[str, Any]) -> dict[str, Any]:
    network = {}
    if isinstance(event.get("network"), dict):
        network.update(event["network"])
    if isinstance(event.get("metadata"), dict):
        network.update(event["metadata"])
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    if isinstance(headers.get("network"), dict):
        network.update(headers["network"])
    return network


def _event_id(
    event: dict[str, Any],
    kind: str,
    timestamp: float,
    entity: str,
    peer: str,
    port: int | None,
    findings: list[str],
) -> str:
    if event.get("event_id"):
        return str(event["event_id"])
    if event.get("flow_id"):
        return str(event["flow_id"])
    seed = f"{kind}:{timestamp}:{entity}:{peer}:{port}:{','.join(findings)}:{event.get('summary') or event.get('label') or ''}"
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


def _summary(event: dict[str, Any], findings: list[str]) -> str:
    if event.get("summary"):
        return str(event["summary"])
    if event.get("label"):
        return f"payload label {event['label']}"
    if findings:
        return ", ".join(findings[:4])
    return str(event.get("type") or event.get("model") or "event")
