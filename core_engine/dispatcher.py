# core_engine/dispatcher.py

import json
from datetime import datetime
from pathlib import Path

from ai_agent.remediation import handle_remediation

BASE_DIR = Path.home() / ".portmap-ai" / "logs"
BASE_DIR.mkdir(parents=True, exist_ok=True)
MASTER_LOG = BASE_DIR / "master_events.log"
REMEDIATION_LOG = BASE_DIR / "remediation_events.jsonl"


def _append_remediation_event(event: dict, logger=None) -> None:
    try:
        with open(REMEDIATION_LOG, "a") as handle:
            handle.write(json.dumps(event) + "\n")
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

    line = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "node_id": node_id,
        "score": score,
        "anomalies": anomalies,
        "ports_sample": ports[:5],  # don’t spam the log
    }

    try:
        with open(MASTER_LOG, "a") as f:
            f.write(json.dumps(line) + "\n")
    except Exception as e:
        print(f"⚠️ Failed to write master log: {e}")

    msg = f"📨 [{node_id}] score={score} anomalies={len(anomalies)} ports={len(ports)}"
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
                    "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    "node_id": node_id,
                    "action": decision.action,
                    "reason": decision.reason,
                    "score": decision.score,
                    "mode": decision.mode,
                }
                ports = payload.get("ports") or []
                if ports:
                    try:
                        top_port = max(ports, key=lambda item: item.get("score", 0.0))
                    except Exception:
                        top_port = ports[0]
                    event["port"] = top_port.get("port")
                    event["program"] = top_port.get("program")
                _append_remediation_event(event, logger)
            if not logger:
                print(f"🛡️ Remediation action: {decision.action} ({decision.reason}) score={decision.score}")
        except Exception as exc:
            error_msg = f"⚠️ Remediation handling failed: {exc}"
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
    return decision
