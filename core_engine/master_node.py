# core_engine/master_node.py

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from pathlib import Path
from urllib import error, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_engine.config_loader import load_node_config
from core_engine.dispatcher import dispatch_alert
from core_engine.logging_utils import configure_logger, update_log_level


def parse_level(level_name: str) -> int:
    try:
        return getattr(logging, level_name.upper())
    except AttributeError:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level_name}'")


def build_remediation_command(payload: dict, decision) -> dict | None:
    if not decision or decision.action == "monitor":
        return None

    connection = None
    ports = payload.get("ports") or []
    if ports:
        try:
            connection = max(ports, key=lambda item: item.get("score", 0.0))
        except Exception:
            connection = ports[0]

    remediation_decision = "review"
    if decision.action == "auto_remediate":
        remediation_decision = "block"
    elif decision.action == "prompt_operator":
        remediation_decision = "review"

    command = {
        "type": "apply_remediation",
        "decision": remediation_decision,
        "reason": decision.reason,
        "score": decision.score,
        "metadata": {"mode": decision.mode},
    }
    if connection:
        command["connection"] = connection
    return command


def _queue_orchestrator_command(orchestrator_url, orchestrator_token, node_id, command, logger):
    if not orchestrator_url or not command:
        return

    url = f"{orchestrator_url.rstrip('/')}/commands"
    payload = json.dumps({"node_id": node_id, "command": command}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if orchestrator_token:
        headers["Authorization"] = f"Bearer {orchestrator_token}"

    req = request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=5):
            logger.debug("Queued remediation command for %s -> %s", node_id, command.get("decision"))
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        logger.warning("Failed to queue remediation command: HTTP %s %s %s", exc.code, exc.reason, body)
    except error.URLError as exc:
        logger.warning("Failed to reach orchestrator for remediation command: %s", exc.reason)


def start_master_server(
    bind_ip: str,
    port: int,
    logger: logging.Logger,
    settings: dict,
    orchestrator_url: str | None,
    orchestrator_token: str | None,
) -> None:
    logger.info("🧠 Master node listening on %s:%s", bind_ip, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((bind_ip, port))
    server_socket.listen()

    try:
        while True:
            conn, addr = server_socket.accept()
            logger.info("🔗 Connection from %s", addr)
            with conn:
                data = conn.recv(65536)
                if not data:
                    logger.debug("Received empty payload from %s", addr)
                    continue
                try:
                    payload = json.loads(data.decode("utf-8", errors="ignore"))
                    logger.info(
                        "📥 Received from %s | score=%s ports=%s",
                        payload.get("node_id", "unknown"),
                        payload.get("score"),
                        len(payload.get("ports", [])),
                    )
                    logger.debug("Payload detail: %s", payload)
                    decision = dispatch_alert(payload, logger=logger, settings=settings)
                    command = build_remediation_command(payload, decision)
                    if command:
                        _queue_orchestrator_command(
                            orchestrator_url,
                            orchestrator_token,
                            payload.get("node_id", "unknown"),
                            command,
                            logger,
                        )
                    ack_message = {"status": "ok"}
                    if decision:
                        ack_message["remediation"] = decision.to_dict()
                    try:
                        conn.sendall(json.dumps(ack_message).encode("utf-8"))
                        logger.debug("Sent ack to %s: %s", addr, ack_message)
                    except Exception as ack_exc:
                        logger.warning("Failed to send ack to %s: %s", addr, ack_exc)
                except Exception as exc:
                    logger.error("⚠️ Error parsing worker payload: %s", exc, exc_info=True)
    except KeyboardInterrupt:
        logger.info("🛑 Master node stopping...")
    finally:
        server_socket.close()


def run_master_node(config_path: str, log_level: int) -> None:
    try:
        config, settings = load_node_config(config_path, defaults={"node_role": "master"})
    except Exception as exc:
        print(f"❌ Failed to load config '{config_path}': {exc}")
        sys.exit(1)

    log_max_bytes = int(config.get("log_max_bytes", settings.get("log_max_bytes", 0)) or 0)
    log_backup_count = int(config.get("log_backup_count", settings.get("log_backup_count", 5)))

    logger = configure_logger(
        "portmap.master",
        "master.log",
        level=log_level,
        max_bytes=log_max_bytes if log_max_bytes > 0 else None,
        backup_count=log_backup_count,
    )
    update_log_level(logger, log_level)

    bind_ip = config.get("master_ip", "0.0.0.0")
    port = int(config.get("port", 9000))
    orchestrator_url = config.get("orchestrator_url") or settings.get("orchestrator_url")
    orchestrator_token = config.get("orchestrator_token") or settings.get("orchestrator_token")
    start_master_server(bind_ip, port, logger, settings, orchestrator_url, orchestrator_token)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portmap-ai Master Node")
    parser.add_argument("--config", required=True, help="Path to master node config JSON")
    parser.add_argument("--log-level", type=parse_level, default=logging.INFO, help="Logging verbosity")
    args = parser.parse_args(argv)
    run_master_node(args.config, args.log_level)


if __name__ == "__main__":
    main()
