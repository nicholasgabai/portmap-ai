from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.attribution.confidence_models import (
    ATTRIBUTION_SAFETY_FLAGS,
    ATTRIBUTION_STATES,
    build_confidence_breakdown,
    classify_attribution_state,
    score_application_attribution_confidence,
)
from core_engine.attribution.signature_learning import build_behavioral_signature_records


APPLICATION_ATTRIBUTION_RECORD_VERSION = 1
DEMO_ATTRIBUTION_LABELS = {"dummy_app", "dummy_db"}
PROBABILISTIC_APPLICATION_MODEL_VERSION = 1
APPLICATION_TOKEN_CANDIDATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("nginx", ("nginx",)),
    ("apache", ("apache", "httpd")),
    ("caddy", ("caddy",)),
    ("postgresql", ("postgres", "postgresql", "psql")),
    ("mysql", ("mysql", "mysqld")),
    ("mariadb", ("mariadb",)),
    ("mongodb", ("mongodb", "mongod", "mongo")),
    ("redis", ("redis",)),
    ("memcached", ("memcached",)),
    ("grafana", ("grafana",)),
    ("prometheus", ("prometheus",)),
    ("elasticsearch", ("elasticsearch", "elastic")),
    ("nextcloud", ("nextcloud",)),
    ("docker", ("docker", "dockerd", "containerd")),
    ("kubernetes", ("kubernetes", "kubelet", "kubectl", "kube_apiserver", "kube_proxy")),
    ("ssh", ("ssh", "sshd")),
    ("sftp", ("sftp",)),
    ("rdp", ("rdp", "xrdp", "remote_desktop")),
    ("vnc", ("vnc", "x11vnc", "tightvnc", "tigervnc")),
    ("ldap", ("ldap", "slapd", "openldap")),
    ("smtp", ("smtp", "postfix", "exim", "sendmail")),
    ("imap", ("imap", "dovecot", "cyrus")),
    ("pop3", ("pop3",)),
    ("ftp", ("ftp", "ftpd", "vsftpd", "proftpd")),
    ("dns", ("dns", "resolver", "named", "bind")),
    ("browser", ("browser", "chrome", "firefox", "safari", "edge")),
)
APPLICATION_PORT_CANDIDATES: dict[int, tuple[str, ...]] = {
    21: ("ftp", "file_transfer"),
    22: ("ssh", "sftp", "remote_access"),
    25: ("smtp", "mail_service"),
    53: ("dns",),
    80: ("http_service", "nginx", "apache", "caddy"),
    110: ("pop3", "mail_service"),
    143: ("imap", "mail_service"),
    389: ("ldap", "directory_service"),
    443: ("https_service", "nginx", "apache", "caddy", "unknown_proxy"),
    465: ("smtp", "mail_service"),
    587: ("smtp", "mail_service"),
    636: ("ldap", "directory_service"),
    993: ("imap", "mail_service"),
    995: ("pop3", "mail_service"),
    2375: ("docker", "container_runtime"),
    2376: ("docker", "container_runtime"),
    3000: ("grafana", "observability_service"),
    3306: ("mysql", "mariadb", "database_service"),
    3389: ("rdp", "remote_access"),
    5432: ("postgresql", "database_service"),
    5601: ("elasticsearch", "observability_service"),
    5900: ("vnc", "remote_access"),
    6379: ("redis", "database_service"),
    6443: ("kubernetes", "container_orchestration"),
    8080: ("http_service", "unknown_proxy"),
    8443: ("https_service", "unknown_proxy"),
    9090: ("prometheus", "observability_service"),
    9200: ("elasticsearch", "observability_service"),
    9300: ("elasticsearch", "observability_service"),
    10250: ("kubernetes", "container_orchestration"),
    11211: ("memcached", "database_service"),
    27017: ("mongodb", "database_service"),
}
APPLICATION_PROTOCOL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "http": ("http_service", "nginx", "apache", "caddy"),
    "https": ("https_service", "nginx", "apache", "caddy", "unknown_proxy"),
    "tls": ("https_service", "unknown_proxy"),
    "ftp": ("ftp", "file_transfer"),
    "sftp": ("sftp", "ssh", "file_transfer"),
    "ssh": ("ssh", "remote_access"),
    "rdp": ("rdp", "remote_access"),
    "vnc": ("vnc", "remote_access"),
    "ldap": ("ldap", "directory_service"),
    "dns": ("dns",),
    "smtp": ("smtp", "mail_service"),
    "imap": ("imap", "mail_service"),
    "pop3": ("pop3", "mail_service"),
    "mysql": ("mysql", "database_service"),
    "mariadb": ("mariadb", "database_service"),
    "mongo": ("mongodb", "database_service"),
    "mongodb": ("mongodb", "database_service"),
    "postgres": ("postgresql", "database_service"),
    "postgresql": ("postgresql", "database_service"),
    "redis": ("redis", "database_service"),
    "memcached": ("memcached", "database_service"),
    "docker": ("docker", "container_runtime"),
    "kubernetes": ("kubernetes", "container_orchestration"),
    "prometheus": ("prometheus", "observability_service"),
    "grafana": ("grafana", "observability_service"),
    "elasticsearch": ("elasticsearch", "observability_service"),
}


class ApplicationAttributionError(ValueError):
    """Raised when dynamic application attribution inputs are malformed."""


def build_probable_application_attributions(
    observation: dict[str, Any],
    *,
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_candidates: int = 3,
) -> list[dict[str, Any]]:
    if not isinstance(observation, dict):
        raise ApplicationAttributionError("observation must be an object")
    timestamp = generated_at or _now()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    hints = _extract_hints(observation, source_mode=mode)
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    candidates = _candidate_classes(hints, signature_rows, source_mode=mode)
    if not candidates:
        candidates = [("Unknown", "Unattributed", "unresolved_live_attribution")]
    records = [
        build_probable_application_attribution(
            observation,
            candidate_app_class=app_class,
            candidate_service_class=service_class,
            candidate_reason=reason,
            signatures=signature_rows,
            generated_at=timestamp,
        )
        for app_class, service_class, reason in candidates
    ]
    return sorted(records, key=lambda item: (-float(item.get("confidence_score") or 0.0), str(item.get("attribution_id") or "")))[: int(max_candidates)]


def build_probable_application_attribution(
    observation: dict[str, Any],
    *,
    candidate_app_class: str | None = None,
    candidate_service_class: str | None = None,
    candidate_reason: str = "metadata_hint",
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise ApplicationAttributionError("observation must be an object")
    timestamp = generated_at or _now()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    hints = _extract_hints(observation, source_mode=mode)
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    conflict_reason = _conflict_reason(hints=hints, source_mode=mode)
    app_class = _safe_candidate(candidate_app_class or _default_app_class(hints, signature_rows), source_mode=mode, fallback="Unknown")
    service_class = _safe_candidate(candidate_service_class or _default_service_class(hints), source_mode=mode, fallback="Unattributed")
    unresolved = app_class == "Unknown" and service_class in {"Unknown", "Unattributed"}
    recurrence_confidence = _signature_recurrence_confidence(signature_rows)
    conflict_penalty = 0.32 if conflict_reason else _candidate_conflict_penalty(app_class=app_class, service_class=service_class, hints=hints)
    confidence = score_application_attribution_confidence(
        process_confidence=_hint_confidence(hints["process_hint"]),
        service_confidence=_hint_confidence(hints["service_hint"]),
        protocol_confidence=_hint_confidence(hints["protocol_hint"]),
        destination_confidence=_hint_confidence(hints["destination_behavior_hint"]),
        flow_confidence=_hint_confidence(hints["flow_behavior_hint"]),
        recurrence_confidence=recurrence_confidence,
        conflict_penalty=conflict_penalty,
    )
    if candidate_reason == "fixture_or_simulated_hint" and mode in {"fixture", "simulated"}:
        confidence = round(min(1.0, confidence + 0.03), 3)
    state = classify_attribution_state(confidence_score=confidence, unresolved=unresolved, conflicting=bool(conflict_reason))
    confidence_breakdown = build_confidence_breakdown(
        process_confidence=_hint_confidence(hints["process_hint"]),
        service_confidence=_hint_confidence(hints["service_hint"]),
        protocol_confidence=_hint_confidence(hints["protocol_hint"]),
        destination_confidence=_hint_confidence(hints["destination_behavior_hint"]),
        flow_confidence=_hint_confidence(hints["flow_behavior_hint"]),
        recurrence_confidence=recurrence_confidence,
        conflict_penalty=conflict_penalty,
    )
    record = {
        "record_type": "probable_application_attribution",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "attribution_id": "app-attr-"
        + _digest(
            {
                "observed_entity_reference": _entity_ref(observation),
                "candidate_app_class": app_class,
                "candidate_service_class": service_class,
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "observed_entity_reference": _entity_ref(observation),
        "candidate_app_class": app_class,
        "candidate_service_class": service_class,
        "process_hint": hints["process_hint"],
        "service_hint": hints["service_hint"],
        "protocol_hint": hints["protocol_hint"],
        "destination_behavior_hint": hints["destination_behavior_hint"],
        "flow_behavior_hint": hints["flow_behavior_hint"],
        "source_mode": mode,
        "data_source": mode,
        "attribution_state": state,
        "confidence_score": confidence,
        "confidence_breakdown": confidence_breakdown,
        "evidence_summary": {
            "candidate_reason": _safe_token(candidate_reason),
            "signature_refs": sorted(str(row.get("signature_id") or "") for row in signature_rows if row.get("signature_id")),
            "signature_count": len(signature_rows),
            "conflict_reason": conflict_reason,
        },
        "advisory_notes": _attribution_notes(state=state, source_mode=mode, conflict_reason=conflict_reason),
        **ATTRIBUTION_SAFETY_FLAGS,
    }
    return record


def build_application_attribution_report(
    observations: Iterable[dict[str, Any]],
    *,
    signature_observations: Iterable[dict[str, Any]] | None = None,
    signatures: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_candidates_per_observation: int = 3,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        observation_rows = [dict(row) for row in observations or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise ApplicationAttributionError("observations must be iterable") from exc
    signature_rows = [dict(row) for row in signatures or [] if isinstance(row, dict)]
    if signature_observations is not None:
        signature_rows.extend(build_behavioral_signature_records(signature_observations, generated_at=timestamp))
    attributions: list[dict[str, Any]] = []
    for row in observation_rows:
        attributions.extend(
            build_probable_application_attributions(
                row,
                signatures=_signatures_for_observation(row, signature_rows),
                generated_at=timestamp,
                max_candidates=max_candidates_per_observation,
            )
        )
    summary = summarize_application_attributions(attributions, generated_at=timestamp)
    return {
        "record_type": "dynamic_application_attribution_report",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "report_id": "dynamic-app-attribution-report-"
        + _digest({"generated_at": timestamp, "attributions": [row["attribution_id"] for row in attributions]})[:16],
        "generated_at": timestamp,
        "attributions": attributions,
        "summary": summary,
        "dashboard_status": build_application_attribution_dashboard(summary=summary, attributions=attributions, generated_at=timestamp),
        "api_status": build_application_attribution_api(summary=summary, attributions=attributions, generated_at=timestamp),
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def summarize_application_attributions(
    attributions: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    return {
        "record_type": "dynamic_application_attribution_summary",
        "record_version": APPLICATION_ATTRIBUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "attribution_count": len(rows),
        "attributed_count": _count_state(rows, "attributed"),
        "probable_count": _count_state(rows, "probable"),
        "possible_count": _count_state(rows, "possible"),
        "unattributed_count": _count_state(rows, "unattributed"),
        "conflicting_count": _count_state(rows, "conflicting"),
        "unknown_count": _count_state(rows, "unknown"),
        "average_confidence_score": _average(rows, "confidence_score"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def build_application_attribution_dashboard(
    *,
    summary: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("conflicting_count") or 0) else "degraded" if int(summary.get("unattributed_count") or 0) else "ok"
    return {
        "record_type": "dynamic_application_attribution_dashboard",
        "panel": "dynamic_application_attribution",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "attribution_count": int(summary.get("attribution_count") or 0),
            "probable_count": int(summary.get("probable_count") or 0),
            "possible_count": int(summary.get("possible_count") or 0),
            "unattributed_count": int(summary.get("unattributed_count") or 0),
            "average_confidence_score": float(summary.get("average_confidence_score") or 0.0),
        },
        "rows": [
            {
                "attribution_id": row.get("attribution_id"),
                "observed_entity_reference": row.get("observed_entity_reference"),
                "candidate_app_class": row.get("candidate_app_class"),
                "candidate_service_class": row.get("candidate_service_class"),
                "attribution_state": row.get("attribution_state"),
                "confidence_score": row.get("confidence_score"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def build_application_attribution_api(
    *,
    summary: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    return {
        "record_type": "dynamic_application_attribution_api",
        "status": "review_required" if int(summary.get("conflicting_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "attributions": rows,
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def deterministic_application_attribution_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def build_probabilistic_application_model(
    observation: dict[str, Any],
    *,
    generated_at: str | None = None,
    max_candidates: int = 6,
) -> dict[str, Any]:
    """Build a deterministic probability distribution from existing metadata only."""
    if not isinstance(observation, dict):
        raise ApplicationAttributionError("observation must be an object")
    if max_candidates <= 0:
        raise ApplicationAttributionError("max_candidates must be greater than 0")

    timestamp = generated_at or _now()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    evidence = _probabilistic_evidence(observation, source_mode=mode)
    raw_scores = _probabilistic_candidate_scores(evidence)
    calibration = _probabilistic_calibration(evidence, raw_scores)
    scores = _calibrated_candidate_scores(raw_scores, evidence, calibration)
    if not scores:
        scores = {
            "unknown_application": 0.45,
            "insufficient_metadata": 0.35,
            "unclassified_service": 0.20,
        }

    total = sum(scores.values()) or 1.0
    candidates = [
        _candidate_reasoning_row(label=label, score=score, total=total, evidence=evidence, calibration=calibration)
        for label, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:max_candidates]
    ]
    probability_total = sum(float(row["probability"]) for row in candidates)
    if candidates and probability_total != 1.0:
        candidates[0]["probability"] = round(float(candidates[0]["probability"]) + (1.0 - probability_total), 3)
        candidates[0]["confidence_contribution"] = candidates[0]["probability"]

    top = candidates[0] if candidates else {"candidate": "unknown_application", "probability": 1.0}
    return {
        "record_type": "probabilistic_application_model",
        "record_version": PROBABILISTIC_APPLICATION_MODEL_VERSION,
        "model_id": "prob-app-model-"
        + _digest(
            {
                "entity": _entity_ref(observation),
                "candidates": [(row["candidate"], row["probability"]) for row in candidates],
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "observed_entity_reference": _entity_ref(observation),
        "top_classification": top["candidate"],
        "confidence": float(top["probability"]),
        "candidates": candidates,
        "candidate_count": len(candidates),
        "alternative_candidates": [
            {"candidate": row["candidate"], "probability": row["probability"]} for row in candidates[1:]
        ],
        "candidate_reasoning": [
            {
                "candidate": row["candidate"],
                "reasoning": row["reasoning"],
                "supporting_evidence": row["supporting_evidence"],
                "missing_evidence": row["missing_evidence"],
                "confidence_contribution": row["confidence_contribution"],
            }
            for row in candidates
        ],
        "calibration": calibration,
        "evidence_count": len(evidence["signals"]),
        "evidence_signals": evidence["signals"],
        "source_mode": mode,
        "data_source": mode,
        "model_state": "metadata_only",
        "deterministic": True,
        "training_performed": False,
        "inference_executed": False,
        "automated_action": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def deterministic_probabilistic_application_model_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def normalize_source_mode(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in {"live", "simulated", "fixture", "replay", "unknown"} else "unknown"


def _candidate_classes(hints: dict[str, str], signatures: list[dict[str, Any]], *, source_mode: str) -> list[tuple[str, str, str]]:
    if _is_unresolved(hints):
        return []
    candidates: list[tuple[str, str, str]] = []
    service = hints["service_hint"].lower()
    protocol = hints["protocol_hint"].lower()
    process = hints["process_hint"].lower()
    destination = hints["destination_behavior_hint"].lower()
    flow = hints["flow_behavior_hint"].lower()
    if normalize_source_mode(source_mode) in {"fixture", "simulated"} and (process in DEMO_ATTRIBUTION_LABELS or service in DEMO_ATTRIBUTION_LABELS):
        candidates.append((_safe_candidate(hints["process_hint"], source_mode=source_mode, fallback="Unknown"), _safe_candidate(hints["service_hint"], source_mode=source_mode, fallback="Unattributed"), "fixture_or_simulated_hint"))
    if any(token in service or token in protocol for token in ("https", "http", "tls")):
        candidates.append(("browser_or_web_client", "web_service", "web_protocol_metadata"))
    if "ssh" in service or "ssh" in protocol or "terminal" in process:
        candidates.append(("remote_access_client", "secure_shell_service", "remote_access_metadata"))
    if any(token in service or token in process for token in ("db", "database", "sql", "postgres")):
        candidates.append(("database_client_or_service", "database_service", "database_metadata"))
    if "resolver" in destination or "dns" in service or "dns" in protocol:
        candidates.append(("name_resolution_client", "dns_service", "destination_behavior_metadata"))
    if "recurring" in flow and signatures:
        candidates.append(("recurring_application_behavior", _default_service_class(hints), "recurring_signature_metadata"))
    if not candidates and normalize_source_mode(source_mode) in {"fixture", "simulated"}:
        candidates.append((_safe_candidate(hints["process_hint"], source_mode=source_mode, fallback="Unknown"), _safe_candidate(hints["service_hint"], source_mode=source_mode, fallback="Unattributed"), "fixture_or_simulated_hint"))
    return _dedupe_candidates(candidates)


def _default_app_class(hints: dict[str, str], signatures: list[dict[str, Any]]) -> str:
    candidates = _candidate_classes(hints, signatures, source_mode="unknown")
    return candidates[0][0] if candidates else "Unknown"


def _default_service_class(hints: dict[str, str]) -> str:
    service = hints.get("service_hint") or "Unattributed"
    if service in {"Unknown", "Unattributed"}:
        protocol = hints.get("protocol_hint") or "unknown"
        return protocol if protocol != "unknown" else "Unattributed"
    return service


def _extract_hints(observation: dict[str, Any], *, source_mode: str) -> dict[str, str]:
    return {
        "process_hint": _safe_candidate(observation.get("process_hint") or observation.get("process_attribution"), source_mode=source_mode, fallback="Unknown"),
        "service_hint": _safe_candidate(observation.get("service_hint") or observation.get("service_attribution"), source_mode=source_mode, fallback="Unattributed"),
        "protocol_hint": _safe_token(observation.get("protocol_hint") or observation.get("protocol") or observation.get("application_protocol")),
        "destination_behavior_hint": _safe_destination_hint(observation),
        "flow_behavior_hint": _safe_token(observation.get("flow_behavior_hint") or observation.get("relationship_state") or observation.get("session_state")),
    }


def _safe_candidate(value: Any, *, source_mode: str, fallback: str) -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name") or value.get("value")
    text = str(value or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    if lowered in {"unknown", "none"}:
        return "Unknown"
    if lowered == "unattributed":
        return fallback
    if lowered in DEMO_ATTRIBUTION_LABELS and normalize_source_mode(source_mode) not in {"fixture", "simulated"}:
        return fallback
    return text[:80]


def _safe_destination_hint(observation: dict[str, Any]) -> str:
    if observation.get("domain_hash"):
        return "hashed_destination"
    if observation.get("domain_summary") or observation.get("destination_behavior_hint"):
        return _safe_token(observation.get("destination_behavior_hint") or "redacted_destination")
    return _safe_token(observation.get("destination_class") or "unknown")


def _hint_confidence(value: str) -> float:
    if value in {"", "unknown", "Unknown", "Unattributed", "unattributed"}:
        return 0.0
    if value in {"redacted_destination", "hashed_destination"}:
        return 0.7
    return 0.82


def _probabilistic_evidence(observation: dict[str, Any], *, source_mode: str) -> dict[str, Any]:
    process = _safe_candidate(
        observation.get("process_hint")
        or observation.get("program")
        or observation.get("process")
        or observation.get("process_attribution"),
        source_mode=source_mode,
        fallback="Unknown",
    )
    service = _safe_candidate(
        observation.get("service_hint")
        or observation.get("service")
        or observation.get("service_name")
        or observation.get("service_attribution"),
        source_mode=source_mode,
        fallback="Unattributed",
    )
    protocol = _safe_token(
        observation.get("protocol_hint")
        or observation.get("protocol")
        or observation.get("transport")
        or observation.get("application_protocol")
        or _first_list_value(observation.get("application_protocols"))
    )
    port = _safe_int(
        observation.get("port")
        or observation.get("service_port")
        or observation.get("dst_port")
        or observation.get("destination_port")
        or observation.get("local_port")
    )
    state = _safe_token(observation.get("status") or observation.get("state") or observation.get("flow_state"))
    signals = []
    if process not in {"Unknown", "Unattributed"}:
        signals.append(f"process:{process}")
    if service not in {"Unknown", "Unattributed"}:
        signals.append(f"service:{service}")
    if protocol != "unknown":
        signals.append(f"protocol:{protocol}")
    if port is not None:
        signals.append(f"port:{port}")
    if state != "unknown":
        signals.append(f"state:{state}")
    external_signals = []
    for signal in _existing_signal_values(observation):
        if signal not in signals:
            signals.append(signal)
        external_signals.append(signal)
    return {
        "process": process,
        "service": service,
        "protocol": protocol,
        "port": port,
        "state": state,
        "signals": signals[:12],
        "external_signals": external_signals[:12],
        "candidate_evidence": {},
    }


def _probabilistic_candidate_scores(evidence: dict[str, Any]) -> dict[str, float]:
    scores: dict[str, float] = {}
    candidate_evidence: dict[str, list[str]] = evidence["candidate_evidence"]

    def add(label: str, amount: float, reason: str) -> None:
        safe_label = _safe_token(label)
        if safe_label in {"unknown", "unattributed"}:
            safe_label = "unknown_application"
        scores[safe_label] = scores.get(safe_label, 0.0) + amount
        candidate_evidence.setdefault(safe_label, [])
        if reason not in candidate_evidence[safe_label]:
            candidate_evidence[safe_label].append(reason)

    process = str(evidence.get("process") or "")
    service = str(evidence.get("service") or "")
    protocol = str(evidence.get("protocol") or "")
    port = evidence.get("port")
    state = str(evidence.get("state") or "")

    for label, tokens in APPLICATION_TOKEN_CANDIDATES:
        if any(token in process.lower() for token in tokens):
            add(label, 3.2, f"process:{process}")
        if any(token in service.lower() for token in tokens):
            add(label, 2.4, f"service:{service}")

    if service not in {"", "Unknown", "Unattributed"}:
        add(service, 1.6, f"service:{service}")
    if protocol != "unknown":
        for label in APPLICATION_PROTOCOL_CANDIDATES.get(protocol, ()):
            add(label, 1.5, f"protocol:{protocol}")
    if port is not None:
        for label in APPLICATION_PORT_CANDIDATES.get(port, ()):
            add(label, 2.0, f"port:{port}")
    for signal in evidence.get("external_signals", []):
        for label in _candidate_labels_from_text(signal):
            add(label, 1.1, f"signal:{signal}")
    if state in {"listen", "listening", "established", "open"}:
        for label in list(scores):
            add(label, 0.25, f"state:{state}")

    return scores


def _probabilistic_calibration(evidence: dict[str, Any], scores: dict[str, float]) -> dict[str, Any]:
    if not scores:
        return {
            "quality": 0.45,
            "unknown_probability": 0.45,
            "evidence_strength": "insufficient",
            "conflicting_evidence": False,
            "factors": ["insufficient_metadata"],
        }

    top_label = max(scores.items(), key=lambda item: (item[1], item[0]))[0]
    reason_types_by_label = _candidate_reason_types(evidence)
    top_types = reason_types_by_label.get(top_label, set())
    factors: list[str] = []
    quality = 0.15

    strong_types = top_types.intersection({"process", "service", "signal"})
    if "process" in strong_types:
        quality += 0.34
        factors.append("process_match")
    if "service" in strong_types:
        quality += 0.24
        factors.append("service_match")
    if "signal" in strong_types:
        quality += 0.30
        factors.append("fingerprint_or_signal_match")
    if "port" in top_types:
        quality += 0.14
        factors.append("port_support")
    if "protocol" in top_types:
        quality += 0.10
        factors.append("protocol_support")
    if "state" in top_types:
        quality += 0.03
        factors.append("state_support")

    has_strong = bool(strong_types)
    if not has_strong and top_types:
        factors.append("generic_metadata_only")
        quality = min(quality, 0.42)
    if top_types == {"port"}:
        quality = min(quality, 0.24)
        factors.append("port_only")
    elif top_types == {"protocol"}:
        quality = min(quality, 0.28)
        factors.append("protocol_only")

    conflicting = _has_conflicting_candidate_evidence(reason_types_by_label)
    if conflicting:
        quality = max(0.18, quality - 0.22)
        factors.append("conflicting_metadata")

    quality = round(min(max(quality, 0.12), 0.88), 3)
    unknown_probability = _unknown_probability_for_quality(quality)
    if conflicting:
        unknown_probability = max(unknown_probability, 0.35)
    return {
        "quality": quality,
        "unknown_probability": unknown_probability,
        "evidence_strength": _evidence_strength_label(quality),
        "conflicting_evidence": conflicting,
        "factors": factors or ["weak_metadata"],
    }


def _calibrated_candidate_scores(
    scores: dict[str, float],
    evidence: dict[str, Any],
    calibration: dict[str, Any],
) -> dict[str, float]:
    if not scores:
        return {}
    calibrated = dict(scores)
    reason_types_by_label = _candidate_reason_types(evidence)
    for label, reason_types in reason_types_by_label.items():
        if label not in calibrated:
            continue
        if reason_types.intersection({"process", "service", "signal"}):
            calibrated[label] *= 1.35
        elif reason_types and reason_types.issubset({"port", "protocol", "state"}):
            calibrated[label] *= 0.82
    total = sum(calibrated.values())
    unknown_probability = float(calibration.get("unknown_probability") or 0.0)
    if total > 0 and "unknown_application" not in calibrated:
        calibrated["unknown_application"] = total * unknown_probability / max(1.0 - unknown_probability, 0.01)
    return calibrated


def _candidate_reason_types(evidence: dict[str, Any]) -> dict[str, set[str]]:
    candidate_evidence = evidence.get("candidate_evidence")
    if not isinstance(candidate_evidence, dict):
        return {}
    return {
        str(label): {_reason_type(reason) for reason in reasons if _reason_type(reason) != "unknown"}
        for label, reasons in candidate_evidence.items()
        if isinstance(reasons, list)
    }


def _reason_type(reason: Any) -> str:
    text = str(reason or "")
    return text.split(":", 1)[0] if ":" in text else "unknown"


def _has_conflicting_candidate_evidence(reason_types_by_label: dict[str, set[str]]) -> bool:
    catalog_labels = _catalog_candidate_labels()
    strong_labels = {
        label
        for label, reason_types in reason_types_by_label.items()
        if reason_types.intersection({"process", "signal"}) or ("service" in reason_types and label in catalog_labels)
    }
    port_labels = {label for label, reason_types in reason_types_by_label.items() if "port" in reason_types}
    if not strong_labels or not port_labels:
        return False
    return any(label not in port_labels for label in strong_labels)


def _catalog_candidate_labels() -> set[str]:
    return {label for label, _tokens in APPLICATION_TOKEN_CANDIDATES}


def _evidence_strength_label(quality: float) -> str:
    if quality >= 0.68:
        return "strong"
    if quality >= 0.45:
        return "moderate"
    if quality >= 0.25:
        return "weak"
    return "insufficient"


def _unknown_probability_for_quality(quality: float) -> float:
    if quality >= 0.68:
        return round(min(max((1.0 - quality) * 0.45, 0.08), 0.18), 3)
    if quality >= 0.50:
        return round(min(max((1.0 - quality) * 0.55, 0.16), 0.28), 3)
    if quality >= 0.25:
        return round(min(max(1.0 - quality, 0.35), 0.58), 3)
    return 0.58


def _candidate_reasoning_row(
    *,
    label: str,
    score: float,
    total: float,
    evidence: dict[str, Any],
    calibration: dict[str, Any],
) -> dict[str, Any]:
    supporting = _supporting_evidence_for_candidate(label, evidence, calibration)
    missing = _missing_evidence_for_candidate(label, supporting, evidence)
    contribution = round(score / total, 3) if total else 0.0
    return {
        "candidate": label,
        "probability": contribution,
        "confidence_contribution": contribution,
        "supporting_evidence": supporting,
        "missing_evidence": missing,
        "reasoning": _candidate_reasoning_text(label, supporting, missing, calibration),
    }


def _supporting_evidence_for_candidate(
    label: str,
    evidence: dict[str, Any],
    calibration: dict[str, Any],
) -> list[str]:
    candidate_evidence = evidence.get("candidate_evidence")
    if isinstance(candidate_evidence, dict):
        supporting = sorted(str(item) for item in candidate_evidence.get(label, []) if item not in {"", "-", None})
        if supporting:
            return supporting
    if label == "unknown_application":
        generic = _generic_evidence_signals(evidence)
        if generic:
            return generic
        return ["insufficient_metadata"]
    if label == "insufficient_metadata":
        return ["insufficient_metadata"]
    if label == "unclassified_service":
        return ["no_catalog_match"]
    factors = calibration.get("factors") if isinstance(calibration, dict) else None
    if isinstance(factors, list) and factors:
        return [_safe_token(factors[0])]
    return ["weak_metadata"]


def _missing_evidence_for_candidate(label: str, supporting: list[str], evidence: dict[str, Any]) -> list[str]:
    support_types = {_reason_type(item) for item in supporting}
    missing = []
    if "process" not in support_types:
        missing.append("process_match")
    if "service" not in support_types:
        missing.append("service_match")
    if "signal" not in support_types:
        missing.append("fingerprint")
    if label not in {"unknown_application", "insufficient_metadata", "unclassified_service"}:
        if "port" not in support_types and evidence.get("port") is None:
            missing.append("port_context")
        if "protocol" not in support_types and evidence.get("protocol") == "unknown":
            missing.append("protocol_context")
    if label == "insufficient_metadata":
        missing.extend(["process_evidence", "service_evidence"])
    return _dedupe_text(missing)


def _generic_evidence_signals(evidence: dict[str, Any]) -> list[str]:
    generic = []
    protocol = evidence.get("protocol")
    port = evidence.get("port")
    state = evidence.get("state")
    if protocol not in {"", "unknown", None}:
        generic.append(f"protocol:{protocol}")
    if port is not None:
        generic.append(f"port:{port}")
    if state not in {"", "unknown", None}:
        generic.append(f"state:{state}")
    for signal in evidence.get("external_signals", []):
        if signal not in generic:
            generic.append(str(signal))
    return generic[:6]


def _candidate_reasoning_text(
    label: str,
    supporting: list[str],
    missing: list[str],
    calibration: dict[str, Any],
) -> str:
    if label == "unknown_application":
        return "insufficient or generic metadata keeps attribution uncertain"
    if label == "insufficient_metadata":
        return "not enough process, service, or fingerprint evidence"
    if label == "unclassified_service":
        return "observed metadata did not match a known catalog entry"
    strength = calibration.get("evidence_strength") if isinstance(calibration, dict) else "unknown"
    support = ", ".join(supporting[:2]) if supporting else "weak_metadata"
    missing_text = ", ".join(missing[:2]) if missing else "no_major_gap"
    return f"{strength} candidate from {support}; missing {missing_text}"


def _dedupe_text(values: list[str]) -> list[str]:
    rows = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in rows:
            rows.append(text)
    return rows


def _existing_signal_values(observation: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    for key in (
        "score_factors",
        "signals",
        "findings",
        "heuristic_signals",
        "visibility_fingerprint",
        "service_fingerprint",
        "fingerprint",
    ):
        value = observation.get(key)
        if isinstance(value, (list, tuple, set)):
            signals.extend(_safe_token(item) for item in value if not _is_blank_signal(item))
        elif isinstance(value, dict):
            signals.extend(_safe_token(item) for item in value.values() if not _is_blank_signal(item))
        elif not _is_blank_signal(value):
            signals.append(_safe_token(value))
    return signals


def _candidate_labels_from_text(value: Any) -> list[str]:
    text = _safe_token(value)
    labels = []
    for label, tokens in APPLICATION_TOKEN_CANDIDATES:
        if any(token in text for token in tokens):
            labels.append(label)
    return labels


def _is_blank_signal(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip() in {"", "-"})


def _first_list_value(value: Any) -> Any:
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value


def _safe_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _signature_recurrence_confidence(signatures: list[dict[str, Any]]) -> float:
    if not signatures:
        return 0.0
    return round(min(1.0, max(float(row.get("confidence_score") or row.get("recurrence_score") or 0.0) for row in signatures)), 3)


def _candidate_conflict_penalty(*, app_class: str, service_class: str, hints: dict[str, str]) -> float:
    service = service_class.lower()
    protocol = hints.get("protocol_hint", "").lower()
    if service not in {"unknown", "unattributed"} and protocol not in {"", "unknown"}:
        if protocol == "udp" and any(token in service for token in ("ssh", "https", "tls")):
            return 0.22
        if protocol == "icmp" and service not in {"icmp", "diagnostic"}:
            return 0.28
    if app_class == "Unknown":
        return 0.08
    return 0.0


def _conflict_reason(*, hints: dict[str, str], source_mode: str) -> str:
    if normalize_source_mode(source_mode) in {"fixture", "simulated"}:
        return ""
    values = {hints["process_hint"].lower(), hints["service_hint"].lower()}
    if values & DEMO_ATTRIBUTION_LABELS:
        return "demo_label_not_allowed_for_live_source"
    return ""


def _is_unresolved(hints: dict[str, str]) -> bool:
    return (
        hints["process_hint"] in {"Unknown", "Unattributed"}
        and hints["service_hint"] in {"Unknown", "Unattributed"}
        and hints["protocol_hint"] == "unknown"
        and hints["destination_behavior_hint"] == "unknown"
        and hints["flow_behavior_hint"] == "unknown"
    )


def _signatures_for_observation(observation: dict[str, Any], signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    matching = [row for row in signatures if normalize_source_mode(row.get("source_mode") or row.get("learned_from_source_mode") or "unknown") in {mode, "unknown"}]
    return matching or signatures


def _entity_ref(observation: dict[str, Any]) -> str:
    for field in ("observed_entity_reference", "session_reference", "session_id", "flow_reference", "flow_pair_id", "relationship_reference", "record_id"):
        value = observation.get(field)
        if value not in {None, ""}:
            return str(value)[:96]
    return "entity-" + _digest(_extract_hints(observation, source_mode=normalize_source_mode(observation.get("source_mode") or "unknown")))[:16]


def _attribution_notes(*, state: str, source_mode: str, conflict_reason: str) -> list[str]:
    notes = [
        f"attribution state is {state}",
        f"source mode is {source_mode}",
        "metadata-only dynamic attribution; unresolved live attribution remains Unknown or Unattributed",
    ]
    if conflict_reason:
        notes.append(f"operator review recommended: {conflict_reason}")
    return notes


def _dedupe_candidates(candidates: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped = []
    for app_class, service_class, reason in candidates:
        key = (app_class, service_class)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((app_class, service_class, reason))
    return deduped


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("attribution_state") == state)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _safe_token(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return text[:80] if text else "unknown"


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
