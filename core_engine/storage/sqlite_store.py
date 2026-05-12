from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from core_engine.storage.schema import SCHEMA_STATEMENTS, SCHEMA_VERSION


class StorageError(RuntimeError):
    """Raised when local storage cannot complete an operation safely."""


class SQLiteStore:
    """Small local-only SQLite wrapper used by storage repositories."""

    def __init__(self, db_path: str | Path) -> None:
        if not db_path:
            raise StorageError("db_path is required")
        self.db_path = Path(db_path)
        self._connection: sqlite3.Connection | None = None

    @property
    def local_only(self) -> bool:
        return True

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self._ensure_parent()
            self._connection = sqlite3.connect(self.db_path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def initialize_schema(self) -> None:
        connection = self.connect()
        with connection:
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, _now()),
            )

    def schema_versions(self) -> list[int]:
        rows = self.query("SELECT version FROM schema_version ORDER BY version")
        return [int(row["version"]) for row in rows]

    def execute(self, statement: str, parameters: Iterable[Any] = ()) -> sqlite3.Cursor:
        try:
            connection = self.connect()
            with connection:
                return connection.execute(statement, tuple(parameters))
        except sqlite3.Error as exc:
            raise StorageError(str(exc)) from exc

    def query(self, statement: str, parameters: Iterable[Any] = ()) -> list[sqlite3.Row]:
        try:
            cursor = self.connect().execute(statement, tuple(parameters))
            return list(cursor.fetchall())
        except sqlite3.Error as exc:
            raise StorageError(str(exc)) from exc

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _ensure_parent(self) -> None:
        if self.db_path == Path(":memory:"):
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> "SQLiteStore":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _now() -> str:
    return datetime.now(UTC).isoformat()
