from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.events import LocalEvent, event_from_dict, event_to_dict
from core_engine.federation.event_window import copy_event_propagation_window, summarize_event_propagation_window
from core_engine.federation.exchange import build_signed_runtime_summary_envelope, verify_signed_runtime_summary_envelope
from core_engine.federation.signing import SIGNING_RECORD_VERSION, SIGNING_SAFETY_FLAGS, build_verification_status_record, deterministic_digest


EVENT_PROPAGATION_RECORD_VERSION = 1
EVENT_PROPAGATION_STATUSES = frozenset({"accepted", "rejected", "stale", "duplicate", "malformed", "untrusted"})


class DistributedEventPropagationError(ValueError):
    """Raised when distributed event propagation records are malformed."""


def build_distributed_event_envelope(
    event: LocalEvent | dict[str, Any],
    *,
    source_node: dict[str, Any],
    destination_node: dict[str, Any],
    trust_profile: dict[str, Any],
    transport_session: dict[str, Any],
    sequence: int = 1,
    nonce: str = "",
    issued_at: str | None = None,
    expires_at: str | None = None,
    key_reference: str = "keyref:event-propagation-placeholder",
    signature_value: str | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = issued_at or _now()
    event_payload = normalize_event_payload(event)
    event_digest = deterministic_digest(event_payload)
    summary_payload = {
        "record_type": "distributed_event_payload",
        "event": event_payload,
        "event_digest": event_digest,
        "source_node_id": str(source_node.get("node_id") or (source_node.get("identity") or {}).get("node_id") or ""),
        "destination_node_id": str(destination_node.get("node_id") or (destination_node.get("identity") or {}).get("node_id") or ""),
        "local_event_storage_ready": True,
        **SIGNING_SAFETY_FLAGS,
    }
    signed = build_signed_runtime_summary_envelope(
        summary_payload,
        source_node=source_node,
        destination_node=destination_node,
        trust_profile=trust_profile,
        transport_session=transport_session,
        trust_scope_label="event-summary",
        sequence=sequence,
        nonce=nonce,
        issued_at=timestamp,
        expires_at=expires_at,
        key_reference=key_reference,
        signature_value=signature_value,
        source_refs=source_refs,
        metadata=metadata,
    )
    envelope = {
        "record_type": "distributed_event_envelope",
        "record_version": EVENT_PROPAGATION_RECORD_VERSION,
        "event_envelope_id": _stable_id("distributed-event-envelope", signed["envelope_id"], event_digest),
        "event_id": event_payload["event_id"],
        "event_type": event_payload["event_type"],
        "event_digest": event_digest,
        "event_sequence": int(sequence),
        "nonce": signed["nonce"],
        "source_node_id": signed["source_node_id"],
        "destination_node_id": signed["destination_node_id"],
        "transport_session_id": signed["transport_session_id"],
        "trust_scope_label": "event-summary",
        "issued_at": signed["issued_at"],
        "expires_at": signed["expires_at"],
        "event": event_payload,
        "signed_exchange_envelope": signed,
        "source_refs": sorted(set([*list(source_refs or []), f"event:{event_payload['event_id']}", f"node:{signed['source_node_id']}"])),
        "metadata": dict(metadata or {}),
        "propagation_status": "pending",
        "local_event_storage_ready": True,
        "advisory_only": True,
        **SIGNING_SAFETY_FLAGS,
    }
    return envelope


def apply_distributed_event_batch(
    event_envelopes: Iterable[dict[str, Any]],
    *,
    propagation_window: dict[str, Any],
    trust_profile: dict[str, Any],
    transport_sessions: Iterable[dict[str, Any]] | dict[str, dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    window = copy_event_propagation_window(propagation_window)
    transports = _transport_map(transport_sessions)
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for envelope in sorted(_rows(event_envelopes), key=lambda item: (str(item.get("source_node_id") or ""), int(item.get("event_sequence") or 0), str(item.get("event_envelope_id") or ""))):
        signed = envelope.get("signed_exchange_envelope") if isinstance(envelope.get("signed_exchange_envelope"), dict) else {}
        transport = transports.get(str(envelope.get("transport_session_id") or signed.get("transport_session_id") or ""))
        if not transport:
            verified = {
                **signed,
                "exchange_status": "malformed",
                "verification_status": build_verification_status_record(
                    envelope_id=str(signed.get("envelope_id") or envelope.get("event_envelope_id") or ""),
                    payload_digest=str(signed.get("payload_digest") or ""),
                    status="metadata-invalid",
                    errors=["transport session was not provided for event envelope"],
                    verified_at=timestamp,
                ),
            }
        else:
            verified = verify_signed_runtime_summary_envelope(
                signed,
                trust_profile=trust_profile,
                transport_session=transport,
                seen_nonces=window.get("seen_nonces") or [],
                last_sequence_by_node=dict(window.get("last_sequence_by_node") or {}),
                generated_at=timestamp,
            )
        event_record = build_event_propagation_record(envelope, verified, generated_at=timestamp)
        if event_record["propagation_status"] == "accepted" and event_record["event_digest"] in set(window.get("seen_event_digests") or []):
            event_record = {
                **event_record,
                "propagation_status": "duplicate",
                "classification_reason": "event digest has already been seen in propagation window",
                "local_event_storage_ready": False,
                "accepted_at": "",
                "rejected_at": timestamp,
            }
        if event_record["propagation_status"] == "accepted":
            accepted.append(event_record)
            _record_accepted_event(window, event_record)
        else:
            rejected.append(event_record)
            _record_rejected_event(window, event_record)
    summary = summarize_event_propagation_batch(
        window=window,
        accepted_events=accepted,
        rejected_events=rejected,
        generated_at=timestamp,
    )
    cluster_rollup = build_cluster_event_rollup(accepted_events=accepted, rejected_events=rejected, generated_at=timestamp)
    dashboard = build_event_propagation_dashboard_status(summary=summary, cluster_rollup=cluster_rollup, generated_at=timestamp)
    return {
        "record_type": "distributed_event_propagation_batch",
        "record_version": EVENT_PROPAGATION_RECORD_VERSION,
        "batch_id": _stable_id("event-propagation-batch", window["window_id"], timestamp, summary),
        "generated_at": timestamp,
        "propagation_window": {**window, "summary": summarize_event_propagation_window(window, generated_at=timestamp)},
        "accepted_events": accepted,
        "rejected_events": rejected,
        "cluster_event_rollup": cluster_rollup,
        "dashboard_status": dashboard,
        "api_status": dashboard["api"],
        "summary": summary,
        **SIGNING_SAFETY_FLAGS,
    }


def build_event_propagation_record(
    envelope: dict[str, Any],
    verified_exchange: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    verification = verified_exchange.get("verification_status") if isinstance(verified_exchange.get("verification_status"), dict) else {}
    event_payload = envelope.get("event") if isinstance(envelope.get("event"), dict) else {}
    event_digest = str(envelope.get("event_digest") or deterministic_digest(event_payload))
    status = classify_event_update(envelope, verified_exchange)
    return {
        "record_type": "distributed_event_propagation_record",
        "record_version": EVENT_PROPAGATION_RECORD_VERSION,
        "propagation_record_id": _stable_id("event-propagation", envelope.get("event_envelope_id"), status, event_digest),
        "event_envelope_id": str(envelope.get("event_envelope_id") or ""),
        "signed_exchange_envelope_id": str((envelope.get("signed_exchange_envelope") or {}).get("envelope_id") or ""),
        "event_id": str(event_payload.get("event_id") or envelope.get("event_id") or ""),
        "event_type": str(event_payload.get("event_type") or envelope.get("event_type") or ""),
        "event_digest": event_digest,
        "event_sequence": int(envelope.get("event_sequence") or 0),
        "nonce": str(envelope.get("nonce") or ""),
        "source_node_id": str(envelope.get("source_node_id") or ""),
        "destination_node_id": str(envelope.get("destination_node_id") or ""),
        "transport_session_id": str(envelope.get("transport_session_id") or ""),
        "propagation_status": status,
        "classification_reason": _classification_reason(status, verification),
        "verification_status": dict(verification),
        "event": dict(event_payload),
        "local_event_storage_ready": status == "accepted",
        "cluster_health_ready": True,
        "operator_visibility_ready": True,
        "accepted_at": timestamp if status == "accepted" else "",
        "rejected_at": timestamp if status != "accepted" else "",
        "source_refs": list(envelope.get("source_refs") or []),
        **SIGNING_SAFETY_FLAGS,
    }


def classify_event_update(envelope: dict[str, Any], verified_exchange: dict[str, Any]) -> str:
    exchange_status = str(verified_exchange.get("exchange_status") or "rejected")
    verification = verified_exchange.get("verification_status") if isinstance(verified_exchange.get("verification_status"), dict) else {}
    errors = " ".join(str(item) for item in verification.get("errors") or [])
    if exchange_status == "accepted":
        event_payload = envelope.get("event")
        try:
            normalize_event_payload(event_payload if isinstance(event_payload, dict) else {})
        except Exception:
            return "malformed"
        return "accepted"
    if exchange_status in {"replayed"} or "nonce" in errors or "sequence" in errors:
        return "duplicate"
    if exchange_status == "stale" or "expired" in errors or "replay window" in errors:
        return "stale"
    if exchange_status == "untrusted" or "approved" in errors or "trust" in errors:
        return "untrusted"
    if exchange_status == "malformed":
        return "malformed"
    return "rejected"


def summarize_event_propagation_batch(
    *,
    window: dict[str, Any],
    accepted_events: Iterable[dict[str, Any]],
    rejected_events: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    accepted_rows = _rows(accepted_events)
    rejected_rows = _rows(rejected_events)
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for row in [*accepted_rows, *rejected_rows]:
        by_status[row["propagation_status"]] = by_status.get(row["propagation_status"], 0) + 1
        event_type = str(row.get("event_type") or "unknown")
        by_type[event_type] = by_type.get(event_type, 0) + 1
    return {
        "generated_at": timestamp,
        "status": "review_required" if rejected_rows else "ok",
        "window_id": str(window.get("window_id") or ""),
        "event_count": len(accepted_rows) + len(rejected_rows),
        "accepted_event_count": len(accepted_rows),
        "rejected_event_count": len(rejected_rows),
        "stale_event_count": by_status.get("stale", 0),
        "duplicate_event_count": by_status.get("duplicate", 0),
        "malformed_event_count": by_status.get("malformed", 0),
        "by_propagation_status": dict(sorted(by_status.items())),
        "by_event_type": dict(sorted(by_type.items())),
        "last_sequence_by_node": dict(sorted((window.get("last_sequence_by_node") or {}).items())),
        "last_event_digest_by_node": dict(sorted((window.get("last_event_digest_by_node") or {}).items())),
        "administrator_review_required": bool(rejected_rows),
        **SIGNING_SAFETY_FLAGS,
    }


def build_cluster_event_rollup(
    *,
    accepted_events: Iterable[dict[str, Any]],
    rejected_events: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [*_rows(accepted_events), *_rows(rejected_events)]
    by_node: dict[str, dict[str, int]] = {}
    for row in rows:
        node_id = str(row.get("source_node_id") or "unknown")
        status = str(row.get("propagation_status") or "unknown")
        by_node.setdefault(node_id, {})
        by_node[node_id][status] = by_node[node_id].get(status, 0) + 1
    return {
        "record_type": "distributed_event_cluster_rollup",
        "record_version": EVENT_PROPAGATION_RECORD_VERSION,
        "rollup_id": _stable_id("event-cluster-rollup", timestamp, by_node),
        "generated_at": timestamp,
        "source_node_count": len(by_node),
        "event_count": len(rows),
        "accepted_event_count": sum(1 for row in rows if row.get("propagation_status") == "accepted"),
        "rejected_event_count": sum(1 for row in rows if row.get("propagation_status") != "accepted"),
        "by_source_node": {node: dict(sorted(counts.items())) for node, counts in sorted(by_node.items())},
        "cluster_health_ready": True,
        "operator_visibility_ready": True,
        **SIGNING_SAFETY_FLAGS,
    }


def build_event_propagation_dashboard_status(
    *,
    summary: dict[str, Any],
    cluster_rollup: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    status = str(summary.get("status") or "unknown")
    return {
        "record_type": "distributed_event_propagation_status",
        "panel": "distributed_event_propagation",
        "status": status,
        "generated_at": timestamp,
        "metrics": {
            "event_count": int(summary.get("event_count") or 0),
            "accepted_event_count": int(summary.get("accepted_event_count") or 0),
            "rejected_event_count": int(summary.get("rejected_event_count") or 0),
            "duplicate_event_count": int(summary.get("duplicate_event_count") or 0),
            "stale_event_count": int(summary.get("stale_event_count") or 0),
            "source_node_count": int(cluster_rollup.get("source_node_count") or 0),
        },
        "api": {
            "status": status,
            "summary": dict(summary),
            "cluster_rollup": dict(cluster_rollup),
        },
        "recommended_review": bool(summary.get("administrator_review_required")),
        **SIGNING_SAFETY_FLAGS,
    }


def normalize_event_payload(event: LocalEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, LocalEvent):
        return event_to_dict(event)
    if not isinstance(event, dict):
        raise DistributedEventPropagationError("event must be a LocalEvent or event dictionary")
    return event_to_dict(event_from_dict(dict(event)))


def deterministic_event_propagation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _record_accepted_event(window: dict[str, Any], record: dict[str, Any]) -> None:
    node_id = record["source_node_id"]
    window["accepted_event_ids"].append(record["event_id"])
    window["seen_event_digests"] = sorted(set([*window.get("seen_event_digests", []), record["event_digest"]]))
    window["seen_nonces"] = sorted(set([*window.get("seen_nonces", []), record["nonce"]]))
    window["last_sequence_by_node"][node_id] = record["event_sequence"]
    window["last_event_digest_by_node"][node_id] = record["event_digest"]
    window["last_seen_event_by_node"][node_id] = {
        "event_id": record["event_id"],
        "event_digest": record["event_digest"],
        "event_sequence": record["event_sequence"],
        "event_type": record["event_type"],
        **SIGNING_SAFETY_FLAGS,
    }


def _record_rejected_event(window: dict[str, Any], record: dict[str, Any]) -> None:
    window["rejected_event_ids"].append(record["event_id"] or record["event_envelope_id"])


def _transport_map(transport_sessions: Iterable[dict[str, Any]] | dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if isinstance(transport_sessions, dict):
        rows = transport_sessions.values()
    else:
        rows = transport_sessions
    return {str(row.get("session_id") or ""): dict(row) for row in rows or [] if isinstance(row, dict) and row.get("session_id")}


def _classification_reason(status: str, verification: dict[str, Any]) -> str:
    errors = verification.get("errors") if isinstance(verification, dict) else []
    if status == "accepted":
        return "verified event metadata accepted for propagation window"
    if errors:
        return "; ".join(str(item) for item in errors)
    return f"event propagation classified as {status}"


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
