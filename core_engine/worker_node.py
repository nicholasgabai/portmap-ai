# core_engine/worker_node.py
# core_engine/worker_node.py

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_agent.scoring import get_score
from core_engine.config_loader import load_node_config
from core_engine.logging_utils import configure_logger, update_log_level
from core_engine.modules.scanner import basic_scan

DEFAULT_TIMEOUT = 5
DEFAULT_MASTER_IP = "127.0.0.1"
DEFAULT_PORT = 9000


def parse_level(level_name: str) -> int:
    try:
        return getattr(logging, level_name.upper())
    except AttributeError:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level_name}'")


def collect_connections(logger: logging.Logger):
    try:
        connections = basic_scan()
        logger.debug("Collected %d connection(s) from basic_scan()", len(connections))
        return connections
    except Exception as exc:
        logger.warning("basic_scan() failed: %s", exc)
        return []


def build_payload(node_id: str, connections, logger: logging.Logger, autolearn: bool) -> dict:
    payload = {
        "node_id": node_id,
        "timestamp": int(time.time()),
        "ports": [],
        "anomalies": [],
        "score": 0.0,
    }

    if not connections:
        logger.info("⚠️ No connections found — sending heartbeat only.")
        return payload

    total_score = 0.0
    scored = 0
    for connection in connections:
        try:
            score = float(get_score(connection, use_ml=autolearn))
            connection["score"] = score
            total_score += score
            scored += 1
        except Exception as exc:
            logger.warning("scoring failed for %s: %s", connection, exc)

    payload["ports"] = connections
    if scored:
        payload["score"] = round(total_score / scored, 3)
    return payload


def send_to_master(
    node_id: str,
    master_ip: str,
    port: int,
    timeout: int,
    logger: logging.Logger,
    autolearn: bool,
):
    connections = collect_connections(logger)
    payload = build_payload(node_id, connections, logger, autolearn)
    data = json.dumps(payload).encode("utf-8")

    logger.info("🔌 Connecting to master %s:%s with timeout=%ss ...", master_ip, port, timeout)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((master_ip, port))
        logger.info("✅ Connected. Sending payload bytes: %s", len(data))
        sock.sendall(data)
        logger.debug("Payload: %s", payload)

        sock.settimeout(1.0)
        try:
            ack = sock.recv(1024)
            if ack:
                ack_text = ack.decode("utf-8", errors="ignore")
                logger.info("📥 Ack from master: %s", ack_text)
                try:
                    ack_payload = json.loads(ack_text)
                    remediation = ack_payload.get("remediation")
                    if remediation:
                        logger.info(
                            "🛡️ Master remediation response: %s (reason=%s)",
                            remediation.get("action"),
                            remediation.get("reason"),
                        )
                except json.JSONDecodeError:
                    logger.debug("Ack not JSON formatted; raw text logged.")
            else:
                logger.debug("No ack data received.")
        except socket.timeout:
            logger.debug("Ack timeout reached (expected for one-way flow).")
    except Exception as exc:
        logger.error("❌ Failed to send to master %s:%s -> %s", master_ip, port, exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as close_exc:
                logger.debug("Socket close raised but ignored: %s", close_exc)


def run_worker(config: dict, settings: dict, logger: logging.Logger, continuous: bool = False):
    node_id = config.get("node_id") or socket.gethostname()
    master_ip = config.get("master_ip", DEFAULT_MASTER_IP)
    port = int(config.get("port", DEFAULT_PORT))
    timeout = int(config.get("timeout", DEFAULT_TIMEOUT))
    interval = int(config.get("scan_interval", 0))
    autolearn = bool(settings.get("enable_autolearn"))

    logger.info(
        "Worker starting | node_id=%s master=%s:%s interval=%ss autolearn=%s",
        node_id,
        master_ip,
        port,
        interval or "disabled",
        autolearn,
    )

    def execute_cycle():
        send_to_master(
            node_id=node_id,
            master_ip=master_ip,
            port=port,
            timeout=timeout,
            logger=logger,
            autolearn=autolearn,
        )

    execute_cycle()
    if continuous:
        interval = interval or 5
        logger.info("🔁 Continuous mode enabled; sleeping %ss between scans.", interval)
        try:
            while True:
                time.sleep(interval)
                execute_cycle()
        except KeyboardInterrupt:
            logger.info("🛑 Worker node stopping...")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portmap-ai Worker Node")
    parser.add_argument("--config", required=True, help="Path to worker node config JSON")
    parser.add_argument("--continuous", action="store_true", help="Enable continuous scan loop")
    parser.add_argument("--log-level", type=parse_level, default=logging.INFO, help="Logging verbosity")
    args = parser.parse_args(argv)

    try:
        config, settings = load_node_config(args.config, defaults={"node_role": "worker"})
    except Exception as exc:
        print(f"❌ Failed to load config '{args.config}': {exc}")
        sys.exit(1)

    log_max_bytes = int(config.get("log_max_bytes", settings.get("log_max_bytes", 0)) or 0)
    log_backup_count = int(config.get("log_backup_count", settings.get("log_backup_count", 5)))

    logger = configure_logger(
        "portmap.worker",
        "worker.log",
        level=args.log_level,
        max_bytes=log_max_bytes if log_max_bytes > 0 else None,
        backup_count=log_backup_count,
    )
    update_log_level(logger, args.log_level)

    run_worker(config, settings, logger, continuous=args.continuous)


if __name__ == "__main__":
    main()
