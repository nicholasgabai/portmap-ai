from __future__ import annotations

import json
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable
from urllib.parse import urlparse

from core_engine.api.routes_assets import assets_response
from core_engine.api.routes_events import events_response
from core_engine.api.routes_health import health_response
from core_engine.api.routes_nodes import nodes_response
from core_engine.api.routes_snapshots import snapshots_response
from core_engine.api.routes_topology import topology_response


DEFAULT_LOCAL_API_HOST = "127.0.0.1"
DEFAULT_LOCAL_API_PORT = 9200


@dataclass(slots=True)
class LocalAPIApp:
    """Small local-only read API facade for dashboard and operator tooling."""

    bind_host: str = DEFAULT_LOCAL_API_HOST
    port: int = DEFAULT_LOCAL_API_PORT
    repository: Any | None = None
    node_registry: Any | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    snapshots: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    topology_edges: list[dict[str, Any]] = field(default_factory=list)
    generated_at: Callable[[], str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.bind_host, str) or not self.bind_host.strip():
            raise ValueError("bind_host must be a non-empty string")
        if not isinstance(self.port, int) or self.port <= 0:
            raise ValueError("port must be a positive integer")

    @property
    def local_only(self) -> bool:
        return self.bind_host in {"127.0.0.1", "localhost", "::1"}

    def get(self, path: str) -> tuple[int, dict[str, Any]]:
        return self.handle_request("GET", path)

    def handle_request(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
        if method.upper() != "GET":
            return HTTPStatus.METHOD_NOT_ALLOWED, _error_response("method_not_allowed", self._generated_at())
        route_path = urlparse(path).path
        routes: dict[str, Callable[[LocalAPIApp], dict[str, Any]]] = {
            "/health": health_response,
            "/events": events_response,
            "/assets": assets_response,
            "/snapshots": snapshots_response,
            "/nodes": nodes_response,
            "/topology": topology_response,
        }
        route = routes.get(route_path)
        if route is None:
            return HTTPStatus.NOT_FOUND, _error_response("not_found", self._generated_at())
        return HTTPStatus.OK, route(self)

    def make_handler(self) -> type[BaseHTTPRequestHandler]:
        app = self

        class LocalAPIHandler(BaseHTTPRequestHandler):
            server_version = "PortMapLocalAPI/1.0"

            def do_GET(self) -> None:
                status, payload = app.handle_request("GET", self.path)
                self._send_json(status, payload)

            def do_POST(self) -> None:
                status, payload = app.handle_request("POST", self.path)
                self._send_json(status, payload)

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(int(status))
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:  # pragma: no cover
                return

        return LocalAPIHandler

    def _generated_at(self) -> str:
        if self.generated_at is not None:
            return self.generated_at()
        from datetime import UTC, datetime

        return datetime.now(UTC).isoformat()


def create_local_api_app(
    *,
    bind_host: str = DEFAULT_LOCAL_API_HOST,
    port: int = DEFAULT_LOCAL_API_PORT,
    repository: Any | None = None,
    node_registry: Any | None = None,
    events: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
    snapshots: list[dict[str, Any]] | None = None,
    nodes: list[dict[str, Any]] | None = None,
    topology_edges: list[dict[str, Any]] | None = None,
    generated_at: Callable[[], str] | None = None,
) -> LocalAPIApp:
    return LocalAPIApp(
        bind_host=bind_host,
        port=port,
        repository=repository,
        node_registry=node_registry,
        events=events or [],
        assets=assets or [],
        snapshots=snapshots or [],
        nodes=nodes or [],
        topology_edges=topology_edges or [],
        generated_at=generated_at,
    )


def _error_response(error: str, generated_at: str) -> dict[str, Any]:
    return {
        "status": "error",
        "error": error,
        "generated_at": generated_at,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }
