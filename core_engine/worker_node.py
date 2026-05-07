# core_engine/worker_node.py
# core_engine/worker_node.py

from __future__ import annotations

import argparse
import json
import logging
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib import error, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_agent.scoring import get_score
from core_engine.command_audit import record_command_event
from core_engine.config_loader import PROJECT_ROOT, load_node_config
from core_engine.config_validation import require_valid_config
from core_engine.logging_utils import configure_logger, update_log_level
from core_engine.platform_utils import local_node_address
from core_engine.modules.scanner import basic_scan
from core_engine.firewall_hooks import configure_firewall
from core_engine.tls_utils import create_client_context, merge_tls_config

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
    tls_context: ssl.SSLContext | None = None,
    tls_config: dict | None = None,
):
    connections = collect_connections(logger)
    payload = build_payload(node_id, connections, logger, autolearn)
    data = json.dumps(payload).encode("utf-8")

    logger.info("🔌 Connecting to master %s:%s with timeout=%ss ...", master_ip, port, timeout)
    sock = None
    try:
        raw_sock = socket.create_connection((master_ip, port), timeout=timeout)
        if tls_context:
            server_hostname = None
            if tls_context.check_hostname:
                server_hostname = (tls_config or {}).get("server_hostname") or master_ip
            sock = tls_context.wrap_socket(raw_sock, server_hostname=server_hostname)
        else:
            sock = raw_sock
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


# --------------------------------------------------------------------------- #
# Orchestrator helpers
# --------------------------------------------------------------------------- #


def _call_orchestrator(orchestrator_url: str | None, orchestrator_token: str | None, endpoint: str, payload: dict) -> dict:
    if not orchestrator_url:
        return {}
    url = f"{orchestrator_url.rstrip('/')}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if orchestrator_token:
        headers["Authorization"] = f"Bearer {orchestrator_token}"

    req = request.Request(url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=5) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def _register_with_orchestrator(logger: logging.Logger, runtime: dict, orchestrator_url: str | None, orchestrator_token: str | None) -> None:
    try:
        payload = {
            "node_id": runtime["node_id"],
            "role": "worker",
            "address": local_node_address(),
            "meta": {
                "master_ip": runtime["master_ip"],
                "port": runtime["port"],
                "interval": runtime["interval"] or 0,
                "autolearn": runtime.get("autolearn", False),
            },
        }
        _call_orchestrator(orchestrator_url, orchestrator_token, "/register", payload)
        logger.info("Registered worker with orchestrator at %s", orchestrator_url)
    except Exception as exc:
        logger.warning("Failed to register with orchestrator: %s", exc)


def _send_heartbeat(logger: logging.Logger, runtime: dict, orchestrator_url: str | None, orchestrator_token: str | None) -> dict:
    try:
        payload = {
            "node_id": runtime["node_id"],
            "status": "online",
            "meta": {
                "interval": runtime["interval"] or 0,
                "autolearn": runtime.get("autolearn", False),
            },
        }
        return _call_orchestrator(orchestrator_url, orchestrator_token, "/heartbeat", payload) or {}
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        logger.warning("Heartbeat failed HTTP %s %s: %s", exc.code, exc.reason, body)
        if exc.code == 404:
            return {"_register_required": True}
    except Exception as exc:
        logger.warning("Heartbeat to orchestrator failed: %s", exc)
    return {}


def _heartbeat_with_reregister(logger: logging.Logger, runtime: dict, orchestrator_url: str | None, orchestrator_token: str | None) -> dict:
    response = _send_heartbeat(logger, runtime, orchestrator_url, orchestrator_token)
    if response.get("_register_required"):
        logger.info("Worker registration missing at orchestrator; re-registering %s", runtime.get("node_id"))
        _register_with_orchestrator(logger, runtime, orchestrator_url, orchestrator_token)
        response = _send_heartbeat(logger, runtime, orchestrator_url, orchestrator_token)
    return response


def _process_commands(logger: logging.Logger, runtime: dict, commands: list[dict]) -> bool:
    extra_scan = False
    for cmd in commands:
        cmd_type = cmd.get("type")
        node_id = runtime.get("node_id") or socket.gethostname()
        record_command_event(node_id, cmd, "received", logger=logger)
        if cmd_type == "scan_now":
            extra_scan = True
            record_command_event(node_id, cmd, "applied", result={"extra_scan": True}, logger=logger)
        elif cmd_type == "set_interval":
            try:
                new_interval = int(cmd.get("value", 0))
                if new_interval > 0:
                    runtime["interval"] = new_interval
                    logger.info("Interval updated via orchestrator: %ss", new_interval)
                    record_command_event(node_id, cmd, "applied", result={"interval": new_interval}, logger=logger)
                else:
                    raise ValueError("interval must be greater than 0")
            except Exception as exc:
                logger.warning("Invalid interval command: %s", exc)
                record_command_event(node_id, cmd, "failed", error=str(exc), logger=logger)
        elif cmd_type == "set_autolearn":
            runtime["autolearn"] = bool(cmd.get("value"))
            logger.info("Autolearn toggled via orchestrator: %s", runtime["autolearn"])
            record_command_event(
                node_id,
                cmd,
                "applied",
                result={"autolearn": runtime["autolearn"]},
                logger=logger,
            )
        elif cmd_type == "reload_config":
            logger.info("Reload config command received (not implemented for worker loop)")
            record_command_event(
                node_id,
                cmd,
                "ignored",
                error="reload_config is not implemented in worker loop",
                logger=logger,
            )
        elif cmd_type == "apply_remediation":
            logger.info("Remediation command received (handled by agent_service in full mode): %s", cmd)
            record_command_event(
                node_id,
                cmd,
                "ignored",
                error="apply_remediation is handled by agent_service",
                logger=logger,
            )
        else:
            logger.warning("Unknown orchestrator command: %s", cmd_type)
            record_command_event(node_id, cmd, "ignored", error="unknown command", logger=logger)
    return extra_scan


def run_worker(
    config: dict,
    settings: dict,
    logger: logging.Logger,
    continuous: bool = False,
    config_path: str | None = None,
    defaults: dict | None = None,
    profile: str | None = None,
    watch_config: bool = False,
    watch_interval: float = 5.0,
):
    runtime = {
        "node_id": config.get("node_id") or socket.gethostname(),
        "master_ip": config.get("master_ip", DEFAULT_MASTER_IP),
        "port": int(config.get("port", DEFAULT_PORT)),
        "timeout": int(config.get("timeout", DEFAULT_TIMEOUT)),
        "interval": int(config.get("scan_interval", 0)),
        "autolearn": bool(settings.get("enable_autolearn")),
        "orchestrator_url": config.get("orchestrator_url") or settings.get("orchestrator_url"),
        "orchestrator_token": config.get("orchestrator_token") or settings.get("orchestrator_token"),
    }

    if continuous:
        runtime["interval"] = runtime["interval"] or 5

    interval_display = runtime["interval"] if continuous else (runtime["interval"] or "disabled")
    logger.info(
        "Worker starting | node_id=%s master=%s:%s interval=%ss autolearn=%s",
        runtime["node_id"],
        runtime["master_ip"],
        runtime["port"],
        interval_display,
        runtime["autolearn"],
    )

    update_lock = threading.Lock()
    tls_config = merge_tls_config(settings.get("tls"), config.get("tls"))
    tls_context = create_client_context(tls_config) if tls_config.get("enabled") else None

    def apply_updates(new_config: dict, new_settings: dict, announce: bool = True) -> None:
        nonlocal tls_config, tls_context
        changes = []
        with update_lock:
            for key, default_value, cast in [
                ("master_ip", DEFAULT_MASTER_IP, str),
                ("port", DEFAULT_PORT, int),
                ("timeout", DEFAULT_TIMEOUT, int),
            ]:
                new_value = new_config.get(key, runtime[key])
                if new_value is None:
                    new_value = default_value
                try:
                    new_value = cast(new_value)
                except Exception:
                    continue
                if new_value != runtime[key]:
                    runtime[key] = new_value
                    changes.append(f"{key}->{new_value}")

            if continuous:
                new_interval = new_config.get("scan_interval")
                if new_interval is not None:
                    try:
                        new_interval = int(new_interval)
                    except Exception:
                        new_interval = runtime["interval"]
                    effective = new_interval or 5
                    if effective != runtime["interval"]:
                        runtime["interval"] = effective
                        changes.append(f"interval->{effective}")

            new_autolearn = bool(new_settings.get("enable_autolearn", runtime["autolearn"]))
            if new_autolearn != runtime["autolearn"]:
                runtime["autolearn"] = new_autolearn
                changes.append(f"autolearn->{new_autolearn}")

            new_orch_url = new_config.get("orchestrator_url") or new_settings.get("orchestrator_url")
            if new_orch_url and new_orch_url != runtime.get("orchestrator_url"):
                runtime["orchestrator_url"] = new_orch_url
                changes.append("orchestrator_url")

            new_orch_token = new_config.get("orchestrator_token") or new_settings.get("orchestrator_token")
            if new_orch_token and new_orch_token != runtime.get("orchestrator_token"):
                runtime["orchestrator_token"] = new_orch_token
                changes.append("orchestrator_token")

        firewall_cfg = new_settings.get("firewall")
        if firewall_cfg is not None:
            configure_firewall(firewall_cfg, logger)
            changes.append("firewall")

        tls_cfg_new = new_settings.get("tls") or new_config.get("tls")
        if tls_cfg_new is not None:
            tls_config = merge_tls_config(new_settings.get("tls"), new_config.get("tls"))
            tls_context = create_client_context(tls_config) if tls_config.get("enabled") else None
            changes.append("tls")

        if announce and changes:
            logger.info("🔄 Applied config update: %s", ", ".join(changes))

    apply_updates(config, settings, announce=False)
    configure_firewall(settings.get("firewall"), logger)

    if runtime.get("orchestrator_url"):
        _register_with_orchestrator(logger, runtime, runtime.get("orchestrator_url"), runtime.get("orchestrator_token"))

    def execute_cycle():
        with update_lock:
            node_id = runtime["node_id"]
            master_ip = runtime["master_ip"]
            port = runtime["port"]
            timeout = runtime["timeout"]
            autolearn = runtime["autolearn"]
            context = tls_context
            tls_cfg = tls_config
            orchestrator_url = runtime.get("orchestrator_url")
            orchestrator_token = runtime.get("orchestrator_token")

        extra_scan = False
        if orchestrator_url:
            response = _heartbeat_with_reregister(logger, runtime, orchestrator_url, orchestrator_token)
            if isinstance(response, dict):
                extra_scan = _process_commands(logger, runtime, response.get("commands", []))
        send_to_master(
            node_id=node_id,
            master_ip=master_ip,
            port=port,
            timeout=timeout,
            logger=logger,
            autolearn=autolearn,
            tls_context=context,
            tls_config=tls_cfg,
        )
        if orchestrator_url and extra_scan:
            logger.info("Executing orchestrator-triggered scan")
            send_to_master(
                node_id=node_id,
                master_ip=master_ip,
                port=port,
                timeout=timeout,
                logger=logger,
                autolearn=runtime["autolearn"],
                tls_context=context,
                tls_config=tls_cfg,
            )

    stop_event = threading.Event()

    def watch_loop():
        if not config_path:
            return
        path = Path(config_path).expanduser()
        if not path.is_absolute():
            path = (PROJECT_ROOT / config_path).resolve()
        last_mtime = path.stat().st_mtime if path.exists() else None
        while not stop_event.is_set():
            stop_event.wait(watch_interval)
            if stop_event.is_set():
                break
            try:
                mtime = path.stat().st_mtime
            except FileNotFoundError:
                continue
            if last_mtime is None or mtime > last_mtime:
                last_mtime = mtime
                try:
                    new_config, new_settings = load_node_config(
                        config_path,
                        defaults=defaults,
                        profile=profile,
                    )
                    require_valid_config(new_config, new_settings, path=config_path, expected_role="worker")
                    apply_updates(new_config, new_settings)
                except Exception as exc:
                    logger.warning("Config reload failed: %s", exc)

    watcher_thread: threading.Thread | None = None
    if watch_config and config_path:
        watcher_thread = threading.Thread(target=watch_loop, daemon=True)
        watcher_thread.start()
        logger.info("👀 Watching %s for changes (every %ss)", config_path, watch_interval)

    execute_cycle()
    if continuous:
        logger.info("🔁 Continuous mode enabled; sleeping %ss between scans.", runtime["interval"])
        try:
            while True:
                time.sleep(runtime["interval"] or 5)
                execute_cycle()
        except KeyboardInterrupt:
            logger.info("🛑 Worker node stopping...")

    if watcher_thread:
        stop_event.set()
        watcher_thread.join(timeout=watch_interval + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portmap-ai Worker Node")
    parser.add_argument("--config", required=True, help="Path to worker node config JSON")
    parser.add_argument("--continuous", action="store_true", help="Enable continuous scan loop")
    parser.add_argument("--profile", help="Config profile name to load before the config file")
    parser.add_argument("--watch-config", action="store_true", help="Watch the config file for changes and hot-reload")
    parser.add_argument("--watch-interval", type=float, default=5.0, help="Seconds between config file checks when watching")
    parser.add_argument("--tls", action="store_true", help="Force TLS enabled (overrides config)")
    parser.add_argument("--log-level", type=parse_level, default=logging.INFO, help="Logging verbosity")
    args = parser.parse_args(argv)

    defaults = {"node_role": "worker"}
    if args.profile:
        defaults["profile"] = args.profile
    try:
        config, settings = load_node_config(args.config, defaults=defaults, profile=args.profile)
        validation = require_valid_config(config, settings, path=args.config, expected_role="worker")
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
    for warning in validation.warnings:
        logger.warning("Config warning: %s", warning)

    if args.tls:
        config.setdefault("tls", {})
        config["tls"]["enabled"] = True

    run_worker(
        config,
        settings,
        logger,
        continuous=args.continuous,
        config_path=args.config,
        defaults=defaults,
        profile=args.profile,
        watch_config=args.watch_config,
        watch_interval=args.watch_interval,
    )


if __name__ == "__main__":
    main()
