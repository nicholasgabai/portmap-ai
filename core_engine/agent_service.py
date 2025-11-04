# core_engine/agent_service.py

from __future__ import annotations

import json
import logging
import socket
import threading
from pathlib import Path
from typing import Optional
from urllib import error, request

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_engine.config_loader import load_node_config
from core_engine.logging_utils import configure_logger, update_log_level
from core_engine.worker_node import DEFAULT_MASTER_IP, DEFAULT_PORT, DEFAULT_TIMEOUT, send_to_master
from core_engine.firewall_hooks import execute_firewall_action


class BackgroundAgent:
    """
    Lightweight background agent that reuses the worker scan cycle in a daemon thread.
    Intended for early experimentation before a full-fledged service manager exists.
    """

    def __init__(self, config_path: str, log_level: int = logging.INFO, interval_override: Optional[int] = None):
        self.config_path = config_path
        self.log_level = log_level
        self.interval_override = interval_override
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._reload_config()

        log_max_bytes = int(self.config.get("log_max_bytes", self.settings.get("log_max_bytes", 0)) or 0)
        log_backup_count = int(self.config.get("log_backup_count", self.settings.get("log_backup_count", 5)))

        self.logger = configure_logger(
            "portmap.agent",
            "agent.log",
            level=log_level,
            max_bytes=log_max_bytes if log_max_bytes > 0 else None,
            backup_count=log_backup_count,
        )
        update_log_level(self.logger, log_level)

    def _reload_config(self):
        self.config, self.settings = load_node_config(self.config_path, defaults={"node_role": "worker"})
        self.node_id = self.config.get("node_id") or socket.gethostname()
        self.master_ip = self.config.get("master_ip", DEFAULT_MASTER_IP)
        self.port = int(self.config.get("port", DEFAULT_PORT))
        self.timeout = int(self.config.get("timeout", DEFAULT_TIMEOUT))
        interval = int(self.config.get("scan_interval", 5)) or 5
        self.interval = self.interval_override or interval
        self.autolearn = bool(self.settings.get("enable_autolearn"))
        self.orchestrator_url = self.config.get("orchestrator_url") or self.settings.get("orchestrator_url")
        self.orchestrator_token = self.config.get("orchestrator_token") or self.settings.get("orchestrator_token")

    def start(self):
        if self._thread and self._thread.is_alive():
            return self._thread

        self.logger.info(
            "Starting background agent | node_id=%s master=%s:%s interval=%ss autolearn=%s",
            self.node_id,
            self.master_ip,
            self.port,
            self.interval,
            self.autolearn,
        )

        self._register_with_orchestrator()

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self, wait: bool = True):
        self._stop_event.set()
        if wait and self._thread:
            self._thread.join(timeout=self.interval + 1)
        self.logger.info("Background agent stopped.")

    def _loop(self):
        while not self._stop_event.is_set():
            send_to_master(
                node_id=self.node_id,
                master_ip=self.master_ip,
                port=self.port,
                timeout=self.timeout,
                logger=self.logger,
                autolearn=self.autolearn,
            )

            extra_scan = False
            if self.orchestrator_url:
                try:
                    response = self._send_heartbeat()
                    extra_scan = self._process_commands(response.get("commands", []))
                except Exception as exc:
                    self.logger.warning("Orchestrator heartbeat failed: %s", exc)

            if extra_scan:
                self.logger.info("Executing orchestrator-triggered scan")
                send_to_master(
                    node_id=self.node_id,
                    master_ip=self.master_ip,
                    port=self.port,
                    timeout=self.timeout,
                    logger=self.logger,
                    autolearn=self.autolearn,
                )

            if self._stop_event.wait(self.interval):
                break

    # ------------------------------------------------------------------
    # Orchestrator integration helpers
    # ------------------------------------------------------------------

    def _call_orchestrator(self, endpoint: str, payload: dict) -> dict:
        if not self.orchestrator_url:
            return {}

        url = f"{self.orchestrator_url.rstrip('/')}{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.orchestrator_token:
            headers["Authorization"] = f"Bearer {self.orchestrator_token}"

        req = request.Request(url, data=data, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"HTTP {exc.code} {exc.reason}: {body}")
        except error.URLError as exc:
            raise RuntimeError(f"Connection error: {exc.reason}")

    def _register_with_orchestrator(self) -> None:
        if not self.orchestrator_url:
            return
        payload = {
            "node_id": self.node_id,
            "role": "worker",
            "address": socket.gethostbyname(socket.gethostname()),
            "meta": {
                "master_ip": self.master_ip,
                "port": self.port,
                "interval": self.interval,
            },
        }
        try:
            self._call_orchestrator("/register", payload)
            self.logger.info("Registered with orchestrator at %s", self.orchestrator_url)
        except Exception as exc:
            self.logger.warning("Failed to register with orchestrator: %s", exc)

    def _send_heartbeat(self) -> dict:
        payload = {
            "node_id": self.node_id,
            "status": "online",
            "meta": {
                "interval": self.interval,
                "autolearn": self.autolearn,
            },
        }
        return self._call_orchestrator("/heartbeat", payload) or {}

    def _process_commands(self, commands):
        extra_scan = False
        for cmd in commands:
            cmd_type = cmd.get("type")
            if cmd_type == "scan_now":
                extra_scan = True
            elif cmd_type == "set_interval":
                try:
                    new_interval = int(cmd.get("value", 0))
                    if new_interval > 0:
                        self.interval = new_interval
                        self.logger.info("Interval updated via orchestrator: %ss", self.interval)
                except Exception as exc:
                    self.logger.warning("Invalid interval command: %s", exc)
            elif cmd_type == "set_autolearn":
                self.autolearn = bool(cmd.get("value"))
                self.logger.info("Autolearn toggled via orchestrator: %s", self.autolearn)
            elif cmd_type == "reload_config":
                self.logger.info("Reloading agent configuration per orchestrator command")
                self._reload_config()
            elif cmd_type == "apply_remediation":
                decision = cmd.get("decision", "review")
                connection = cmd.get("connection") or {}
                reason = cmd.get("reason", "")
                self.logger.info(
                    "Applying remediation action from orchestrator: %s (reason=%s)",
                    decision,
                    reason,
                )
                try:
                    execute_firewall_action(connection, decision)
                except Exception as exc:
                    self.logger.error("Failed to execute remediation action: %s", exc)
            else:
                self.logger.warning("Unknown orchestrator command: %s", cmd_type)
        return extra_scan


__all__ = ["BackgroundAgent"]
