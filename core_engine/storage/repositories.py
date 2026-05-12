from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.events import LocalEvent, event_to_dict
from core_engine.storage.sqlite_store import SQLiteStore, StorageError


class LocalStorageRepository:
    """Repository methods for local SQLite visibility records."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store
        self.store.initialize_schema()

    @property
    def local_only(self) -> bool:
        return self.store.local_only

    def insert_event(self, event: LocalEvent | dict[str, Any]) -> int:
        payload = event_to_dict(event) if isinstance(event, LocalEvent) else dict(event)
        event_id = _required(payload, "event_id")
        cursor = self.store.execute(
            """
            INSERT INTO events (event_id, event_type, severity, source, timestamp, message, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                _required(payload, "event_type"),
                _required(payload, "severity"),
                _required(payload, "source"),
                _required(payload, "timestamp"),
                _required(payload, "message"),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_events(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM events ORDER BY id"))

    def insert_snapshot(self, snapshot: dict[str, Any]) -> int:
        payload = dict(snapshot)
        snapshot_id = str(payload.get("snapshot_id") or _stable_id("snapshot", payload))
        payload.setdefault("snapshot_id", snapshot_id)
        cursor = self.store.execute(
            """
            INSERT INTO snapshots (snapshot_id, label, observed_at, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                _optional_str(payload.get("label")),
                _optional_str(payload.get("observed_at")),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_snapshots(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM snapshots ORDER BY id"))

    def insert_asset(self, asset: dict[str, Any]) -> int:
        payload = dict(asset)
        asset_id = str(payload.get("asset_id") or _stable_id("asset", payload))
        payload.setdefault("asset_id", asset_id)
        cursor = self.store.execute(
            """
            INSERT INTO assets (asset_id, host, status, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                asset_id,
                _optional_str(payload.get("host")),
                _optional_str(payload.get("status")),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_assets(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM assets ORDER BY id"))

    def insert_service(self, service: dict[str, Any]) -> int:
        payload = dict(service)
        service_id = str(payload.get("service_id") or _stable_id("service", payload))
        payload.setdefault("service_id", service_id)
        cursor = self.store.execute(
            """
            INSERT INTO services (service_id, target, port, service_name, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                _optional_str(payload.get("target")),
                _optional_int(payload.get("port")),
                _optional_str(payload.get("service") or payload.get("service_name")),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_services(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM services ORDER BY id"))

    def insert_topology_edge(self, edge: dict[str, Any]) -> int:
        payload = dict(edge)
        edge_id = str(payload.get("edge_id") or _stable_id("edge", payload))
        payload.setdefault("edge_id", edge_id)
        cursor = self.store.execute(
            """
            INSERT INTO topology_edges (edge_id, src, dst, protocol, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                edge_id,
                _optional_str(payload.get("src")),
                _optional_str(payload.get("dst")),
                _optional_str(payload.get("protocol")),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_topology_edges(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM topology_edges ORDER BY id"))

    def insert_finding(self, finding: dict[str, Any]) -> int:
        payload = dict(finding)
        finding_id = str(payload.get("finding_id") or _stable_id("finding", payload))
        payload.setdefault("finding_id", finding_id)
        cursor = self.store.execute(
            """
            INSERT INTO findings (finding_id, finding_type, severity, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                _optional_str(payload.get("type") or payload.get("finding_type")),
                _optional_str(payload.get("severity")),
                _to_json(payload),
                _now(),
            ),
        )
        return int(cursor.lastrowid)

    def list_findings(self) -> list[dict[str, Any]]:
        return _decode_rows(self.store.query("SELECT payload_json FROM findings ORDER BY id"))


def _required(payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise StorageError(f"{field_name} is required")
    return value


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise StorageError("port must be an integer when provided") from exc


def _to_json(payload: dict[str, Any]) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
    except TypeError as exc:
        raise StorageError(f"payload is not JSON serializable: {exc}") from exc


def _decode_rows(rows: list[Any]) -> list[dict[str, Any]]:
    return [json.loads(row["payload_json"]) for row in rows]


def _stable_id(prefix: str, payload: dict[str, Any]) -> str:
    digest = sha256(_to_json(payload).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _now() -> str:
    return datetime.now(UTC).isoformat()
