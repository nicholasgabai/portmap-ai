# core_engine/orchestrator.py

from __future__ import annotations

import argparse
import json
import logging
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Callable, Tuple

from core_engine.config_loader import load_node_config
from core_engine.config_validation import require_valid_config
from core_engine.logging_utils import configure_logger, update_log_level
from core_engine.orchestrator_service import OrchestratorState
from core_engine.security import validate_node_identity, verify_bearer_header

try:
    from http.server import HTTPServer
except ImportError:  # pragma: no cover
    from SocketServer import TCPServer as HTTPServer  # type: ignore


def parse_level(level_name: str) -> int:
    try:
        return getattr(logging, level_name.upper())
    except AttributeError:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level_name}'")


def make_handler(state: OrchestratorState, auth_token: str | None, logger: logging.Logger) -> Callable:
    class OrchestratorHandler(BaseHTTPRequestHandler):
        server_version = "PortMapOrchestrator/1.0"

        def _send_json(self, status: int, payload: dict) -> None:
            response = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def _read_json(self) -> dict:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return {}
            body = self.rfile.read(content_length) if content_length else b""
            if not body:
                return {}
            try:
                return json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON body")

        def _check_auth(self) -> bool:
            return verify_bearer_header(self.headers.get("Authorization"), auth_token)

        def do_GET(self) -> None:
            if not self._check_auth():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return

            if self.path == "/healthz":
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return

            if self.path == "/nodes":
                nodes = state.list_nodes()
                self._send_json(HTTPStatus.OK, {"nodes": nodes})
                return

            if self.path == "/metrics":
                metrics = state.get_metrics()
                self._send_json(HTTPStatus.OK, metrics)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def do_POST(self) -> None:
            if not self._check_auth():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            if self.path == "/register":
                missing = [k for k in ("node_id", "role", "address") if k not in payload]
                if missing:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                identity_errors = validate_node_identity(payload.get("node_id"), payload.get("role"))
                if identity_errors:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "; ".join(identity_errors)})
                    return
                node = state.register_node(
                    node_id=payload["node_id"],
                    role=payload["role"],
                    address=payload["address"],
                    metadata=payload.get("meta") or {},
                )
                self._send_json(HTTPStatus.CREATED, {"node": node})
                return

            if self.path == "/heartbeat":
                missing = [k for k in ("node_id", "status") if k not in payload]
                if missing:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                identity_errors = validate_node_identity(payload.get("node_id"), "worker")
                if identity_errors:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "; ".join(identity_errors)})
                    return
                try:
                    result = state.record_heartbeat(
                        node_id=payload["node_id"],
                        status=payload["status"],
                        metadata=payload.get("meta") or {},
                    )
                except KeyError as exc:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.OK, result)
                return

            if self.path == "/commands":
                missing = [k for k in ("node_id", "command") if k not in payload]
                if missing:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                identity_errors = validate_node_identity(payload.get("node_id"), "worker")
                if identity_errors:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "; ".join(identity_errors)})
                    return
                if not isinstance(payload.get("command"), dict):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "command must be an object"})
                    return
                try:
                    state.enqueue_command(node_id=payload["node_id"], command=payload["command"])
                except KeyError as exc:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                    return
                self._send_json(HTTPStatus.ACCEPTED, {"status": "queued"})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def log_message(self, fmt: str, *args: object) -> None:  # pragma: no cover
            logger.info("HTTP %s - %s", self.address_string(), fmt % args)

    return OrchestratorHandler


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def run_orchestrator(config_path: str, log_level: int, profile: str | None = None) -> None:
    try:
        defaults = {"node_role": "orchestrator", "bind_ip": "0.0.0.0", "port": 9100}
        if profile:
            defaults["profile"] = profile
        config, settings = load_node_config(
            config_path,
            defaults=defaults,
            profile=profile,
        )
        validation = require_valid_config(config, settings, path=config_path, expected_role="orchestrator")
    except Exception as exc:
        print(f"❌ Failed to load orchestrator config '{config_path}': {exc}")
        sys.exit(1)

    log_max_bytes = int(config.get("log_max_bytes", settings.get("log_max_bytes", 0)) or 0)
    log_backup_count = int(config.get("log_backup_count", settings.get("log_backup_count", 5)))

    logger = configure_logger(
        "portmap.orchestrator",
        "orchestrator.log",
        level=log_level,
        max_bytes=log_max_bytes if log_max_bytes > 0 else None,
        backup_count=log_backup_count,
    )
    update_log_level(logger, log_level)
    for warning in validation.warnings:
        logger.warning("Config warning: %s", warning)

    bind_ip = config.get("bind_ip", "0.0.0.0")
    port = int(config.get("port", 9100))
    auth_token = config.get("auth_token") or settings.get("orchestrator_token")

    node_stale_after = int(config.get("node_stale_after", settings.get("node_stale_after", 60)) or 0)
    state = OrchestratorState(
        logger=logger,
        stale_after_seconds=node_stale_after if node_stale_after > 0 else None,
    )
    handler_cls = make_handler(state, auth_token, logger)
    server = ThreadedHTTPServer((bind_ip, port), handler_cls)

    logger.info("☁️  Orchestrator listening on %s:%s", bind_ip, port)
    if auth_token:
        logger.info("🔐 Token authentication enabled for orchestrator API")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🛑 Orchestrator shutting down...")
    finally:
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="PortMap-AI Orchestrator Service")
    parser.add_argument("--config", required=True, help="Path to orchestrator config JSON")
    parser.add_argument("--log-level", type=parse_level, default=logging.INFO, help="Logging verbosity")
    parser.add_argument("--profile", help="Config profile name to load before the config file")
    args = parser.parse_args(argv)
    run_orchestrator(args.config, args.log_level, profile=args.profile)


if __name__ == "__main__":
    main()
