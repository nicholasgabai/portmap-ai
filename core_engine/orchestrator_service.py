# core_engine/orchestrator_service.py

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from core_engine.config_loader import DATA_DIR
from core_engine.security import scrub_secrets

STATE_FILE_DEFAULT = DATA_DIR / "orchestrator_state.json"


class OrchestratorState:
    """
    In-memory registry of connected nodes with simple persistence to disk.
    Used by the orchestrator HTTP layer to coordinate master/worker nodes.
    """

    def __init__(self, state_file: Path | str = STATE_FILE_DEFAULT, logger=None, stale_after_seconds: int | None = 60):
        self.state_file = Path(state_file)
        self.logger = logger
        self.stale_after_seconds = stale_after_seconds
        self._lock = threading.Lock()
        self._nodes: Dict[str, Dict[str, object]] = {}
        self._commands: Dict[str, List[Dict[str, object]]] = {}
        self._metrics = {
            "registers": 0,
            "heartbeats": 0,
            "commands_queued": 0,
            "nodes_marked_offline": 0,
        }
        self._load()

    # ------------------------------------------------------------------ #
    # Persistence helpers
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r") as handle:
                payload = json.load(handle)
            self._nodes = payload.get("nodes", {})
            self._commands = {k: list(v) for k, v in payload.get("commands", {}).items()}
        except Exception as exc:
            if self.logger:
                self.logger.warning("Failed to load orchestrator state: %s", exc)

    def _persist(self) -> None:
        data = {"nodes": self._nodes, "commands": self._commands}
        try:
            with open(self.state_file, "w") as handle:
                json.dump(data, handle, indent=2)
        except Exception as exc:
            if self.logger:
                self.logger.error("Failed to persist orchestrator state: %s", exc)

    # ------------------------------------------------------------------ #
    # Node management
    # ------------------------------------------------------------------ #
    def register_node(self, node_id: str, role: str, address: str, metadata: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        now = int(time.time())
        node_payload = {
            "node_id": node_id,
            "role": role,
            "address": address,
            "meta": scrub_secrets(metadata or {}),
            "last_seen": now,
            "status": "registered",
        }
        with self._lock:
            self._nodes[node_id] = node_payload
            self._commands.setdefault(node_id, [])
            self._persist()
            self._metrics["registers"] += 1
        if self.logger:
            self.logger.info("Registered node %s (role=%s address=%s)", node_id, role, address)
        return node_payload

    def record_heartbeat(self, node_id: str, status: str, metadata: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        now = int(time.time())
        with self._lock:
            node = self._nodes.get(node_id)
            if not node:
                raise KeyError(f"Unknown node_id '{node_id}'")
            node["last_seen"] = now
            node["status"] = status
            if metadata:
                node["meta"].update(scrub_secrets(metadata))
            pending = self._commands.get(node_id, [])
            commands = list(pending)
            self._commands[node_id] = []
            self._persist()
            self._metrics["heartbeats"] += 1
        if self.logger:
            self.logger.debug("Heartbeat from %s status=%s", node_id, status)
        return {"node": node, "commands": commands}

    def enqueue_command(self, node_id: str, command: Dict[str, object]) -> None:
        with self._lock:
            if node_id not in self._nodes:
                raise KeyError(f"Unknown node_id '{node_id}'")
            self._commands.setdefault(node_id, []).append(command)
            self._persist()
            self._metrics["commands_queued"] += 1
        if self.logger:
            self.logger.info("Queued command for %s: %s", node_id, command.get("type", "unknown"))

    def mark_stale_nodes(self, now: int | None = None) -> int:
        if not self.stale_after_seconds or self.stale_after_seconds <= 0:
            return 0
        now = now if now is not None else int(time.time())
        cutoff = now - self.stale_after_seconds
        changed = 0
        with self._lock:
            for node in self._nodes.values():
                last_seen = int(node.get("last_seen", 0) or 0)
                if last_seen < cutoff and node.get("status") != "offline":
                    node["status"] = "offline"
                    changed += 1
            if changed:
                self._metrics["nodes_marked_offline"] += changed
                self._persist()
        if changed and self.logger:
            self.logger.warning("Marked %s stale node(s) offline", changed)
        return changed

    def list_nodes(self) -> List[Dict[str, object]]:
        self.mark_stale_nodes()
        with self._lock:
            return list(self._nodes.values())

    def get_node(self, node_id: str) -> Optional[Dict[str, object]]:
        with self._lock:
            node = self._nodes.get(node_id)
            return dict(node) if node else None

    def get_metrics(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._metrics)


__all__ = ["OrchestratorState", "STATE_FILE_DEFAULT"]
