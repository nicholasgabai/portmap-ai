# core_engine/dispatcher.py

import json
from pathlib import Path

from ai_agent.remediation import handle_remediation
from core_engine.audit_events import append_jsonl_event, record_audit_event, utc_timestamp
from core_engine.remediation_safety import firewall_dry_run

BASE_DIR = Path.home() / ".portmap-ai" / "logs"
BASE_DIR.mkdir(parents=True, exist_ok=True)
MASTER_LOG = BASE_DIR / "master_events.log"
REMEDIATION_LOG = BASE_DIR / "remediation_events.jsonl"


def _firewall_dry_run(settings: dict | None) -> bool:
    return firewall_dry_run(settings)


def _append_remediation_event(event: dict, logger=None) -> None:
    try:
        append_jsonl_event(REMEDIATION_LOG, event)
    except Exception as exc:
        message = f"⚠️ Failed to write remediation log: {exc}"
        if logger:
            logger.warning(message)
        else:
            print(message)

def dispatch_alert(payload: dict, logger=None, settings=None):
    """
    Minimal router for incoming worker telemetry.
    - Writes a compact line to master_events.log
    - Prints a short summary
    - Future: fan-out to UI, DB, alerting, remediation pipeline
    """
    node_id = payload.get("node_id", "unknown-node")
    score = payload.get("score", "-")
    anomalies = payload.get("anomalies", [])
    ports = payload.get("ports", [])
    score_factors = []
    if ports:
        try:
            top_port = max(ports, key=lambda item: item.get("score", 0.0))
        except Exception:
            top_port = ports[0]
        score_factors = top_port.get("score_factors") or []
    else:
        top_port = None

    line = {
        "timestamp": utc_timestamp(),
        "event_type": "worker_telemetry",
        "node_id": node_id,
        "score": score,
        "risk_score": score,
        "anomalies": anomalies,
        "ports_sample": ports[:5],  # don’t spam the log
        "score_factors": score_factors,
    }

    try:
        with open(MASTER_LOG, "a") as f:
            f.write(json.dumps(line) + "\n")
    except Exception as e:
        print(f"⚠️ Failed to write master log: {e}")

    factor_suffix = f" factors={','.join(score_factors[:3])}" if score_factors else ""
    msg = f"📨 [{node_id}] score={score} anomalies={len(anomalies)} ports={len(ports)}{factor_suffix}"
    if logger:
        logger.info(msg)
    else:
        print(msg)

    decision = None
    if settings is not None:
        try:
            decision = handle_remediation(payload, settings, logger if logger else None)
            if decision:
                event = {
                    "timestamp": utc_timestamp(),
                    "event_type": "remediation_decision",
                    "node_id": node_id,
                    "action": decision.action,
                    "reason": decision.reason,
                    "score": decision.score,
                    "risk_score": decision.score,
                    "mode": decision.mode,
                    "status": "decided",
                    "dry_run": _firewall_dry_run(settings),
                    "enforcement": "dry_run" if _firewall_dry_run(settings) else "active",
                    "score_factors": score_factors,
                }
                if top_port:
                    event["port"] = top_port.get("port")
                    event["program"] = top_port.get("program")
                    event["protocol"] = top_port.get("protocol")
                    event["status"] = top_port.get("status")
                    event["local"] = top_port.get("local")
                    event["remote"] = top_port.get("remote")
                _append_remediation_event(event, logger)
                record_audit_event(
                    "remediation_decision",
                    node_id=node_id,
                    action=decision.action,
                    status="decided",
                    risk_score=decision.score,
                    source="dispatcher",
                    details=event,
                    logger=logger,
                )
            if not logger:
                print(f"🛡️ Remediation action: {decision.action} ({decision.reason}) score={decision.score}")
        except Exception as exc:
            error_msg = f"⚠️ Remediation handling failed: {exc}"
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
    return decision
