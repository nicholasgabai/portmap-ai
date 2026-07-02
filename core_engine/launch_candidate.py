"""Launch-candidate stabilization helpers.

This module provides deterministic local readiness summaries used to validate
startup behavior, empty states, cache behavior, and cross-pipeline consistency.
It does not start services, perform network calls, mutate runtime state, or
execute remediation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from core_engine.attribution.behavior_graph import build_behavior_graph_model
from core_engine.capture import PacketMetadata
from core_engine.packet_intelligence import PacketIntelligenceEngine


FORBIDDEN_LAUNCH_FIELDS = {
    "payload",
    "payload_body",
    "payload_bytes",
    "raw_packet",
    "raw_bytes",
    "packet_bytes",
    "body",
    "content",
    "secret",
    "token",
    "password",
}


DEFAULT_CONFIG = {
    "refresh_interval_seconds": 5,
    "packet_intelligence_enabled": True,
    "behavior_graph_enabled": True,
    "risk_summary_enabled": True,
    "ai_summary_enabled": True,
    "max_rows": 500,
}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(prefix: str, value: Any, *, length: int = 16) -> str:
    return f"{prefix}-{hashlib.sha256(stable_json(value).encode('utf-8')).hexdigest()[:length]}"


def safe_text(value: Any, default: str = "-") -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    return text or default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(parsed, 0)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, parsed))


def safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: Dict[str, Any] = {}
    for key in sorted(value):
        normalized_key = safe_text(key).lower()
        if normalized_key in FORBIDDEN_LAUNCH_FIELDS:
            continue
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        elif isinstance(item, (list, tuple)):
            safe_items = []
            for entry in item:
                if isinstance(entry, (str, int, float, bool)) or entry is None:
                    safe_items.append(entry)
                elif isinstance(entry, dict):
                    safe_items.append(safe_metadata(entry))
                else:
                    safe_items.append(str(entry))
            result[str(key)] = safe_items
        elif isinstance(item, dict):
            result[str(key)] = safe_metadata(item)
        else:
            result[str(key)] = str(item)
    return result


def validate_launch_config(config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    source = safe_metadata(config or {})
    effective = dict(DEFAULT_CONFIG)
    diagnostics: list[str] = []

    for key in sorted(source):
        if key in DEFAULT_CONFIG:
            effective[key] = source[key]
        else:
            diagnostics.append(f"ignored_unknown_config:{key}")

    effective["refresh_interval_seconds"] = max(1, safe_int(effective.get("refresh_interval_seconds"), 5))
    effective["max_rows"] = max(1, safe_int(effective.get("max_rows"), 500))
    for key in (
        "packet_intelligence_enabled",
        "behavior_graph_enabled",
        "risk_summary_enabled",
        "ai_summary_enabled",
    ):
        effective[key] = bool(effective.get(key))

    return {
        "config_id": stable_id("launch-config", effective),
        "effective_config": effective,
        "diagnostics": sorted(diagnostics),
        "valid": True,
    }


def summarize_startup_paths(paths: Iterable[str | Path] | None = None) -> Dict[str, Any]:
    rows = []
    for path in sorted({safe_text(path) for path in paths or []}):
        item = Path(path)
        rows.append(
            {
                "path": path,
                "exists": item.exists(),
                "is_dir": item.is_dir() if item.exists() else False,
                "is_file": item.is_file() if item.exists() else False,
                "status": "available" if item.exists() else "missing",
            }
        )
    return {
        "path_count": len(rows),
        "missing_count": sum(1 for row in rows if row["status"] == "missing"),
        "paths": rows,
    }


def safe_load_json(path: str | Path) -> Dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
        data = json.loads(text)
    except FileNotFoundError:
        return {"status": "missing", "data": {}, "error": "file_not_found"}
    except json.JSONDecodeError:
        return {"status": "invalid", "data": {}, "error": "invalid_json"}
    except OSError:
        return {"status": "unavailable", "data": {}, "error": "read_failed"}
    return {"status": "loaded", "data": safe_metadata(data if isinstance(data, dict) else {"value": data}), "error": "-"}


class LaunchCandidateStabilizer:
    """Build deterministic release-candidate stabilization summaries."""

    def __init__(self) -> None:
        self._packet_summary_cache: dict[str, Dict[str, Any]] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    def build_summary(
        self,
        *,
        config: Dict[str, Any] | None = None,
        startup_paths: Iterable[str | Path] | None = None,
        packets: Iterable[PacketMetadata | Dict[str, Any]] | None = None,
        protocol_records: Iterable[Dict[str, Any]] | None = None,
        timeline_events: Iterable[Dict[str, Any]] | None = None,
        visualization_models: Iterable[Dict[str, Any]] | None = None,
        hunt_results: Iterable[Dict[str, Any]] | None = None,
        conversations: Iterable[Dict[str, Any]] | None = None,
        behavior_observation: Dict[str, Any] | None = None,
        classification_model: Dict[str, Any] | None = None,
        learning_profile: Dict[str, Any] | None = None,
        risk_cards: Iterable[Dict[str, Any]] | None = None,
        ai_summaries: Iterable[Dict[str, Any]] | None = None,
        generated_at: str = "-",
    ) -> Dict[str, Any]:
        config_summary = validate_launch_config(config)
        startup_summary = summarize_startup_paths(startup_paths)
        packet_summary = (
            self._packet_intelligence_summary(
                packets=packets,
                protocol_records=protocol_records,
                timeline_events=timeline_events,
                visualization_models=visualization_models,
                hunt_results=hunt_results,
                conversations=conversations,
                generated_at=generated_at,
            )
            if config_summary["effective_config"]["packet_intelligence_enabled"]
            else _disabled_summary("packet_intelligence_disabled")
        )
        behavior_summary = (
            _behavior_graph_summary(
                behavior_observation,
                classification_model=classification_model,
                learning_profile=learning_profile,
                generated_at=generated_at,
            )
            if config_summary["effective_config"]["behavior_graph_enabled"]
            else _disabled_summary("behavior_graph_disabled")
        )
        risk_summary = (
            _risk_summary(risk_cards or [])
            if config_summary["effective_config"]["risk_summary_enabled"]
            else _disabled_summary("risk_summary_disabled")
        )
        ai_summary = (
            _ai_summary(ai_summaries or [])
            if config_summary["effective_config"]["ai_summary_enabled"]
            else _disabled_summary("ai_summary_disabled")
        )
        diagnostics = _diagnostics(
            config_summary=config_summary,
            startup_summary=startup_summary,
            packet_summary=packet_summary,
            behavior_summary=behavior_summary,
            risk_summary=risk_summary,
            ai_summary=ai_summary,
        )
        basis = {
            "generated_at": safe_text(generated_at),
            "config": config_summary,
            "startup": startup_summary,
            "packet_summary_id": packet_summary.get("summary_id", "-"),
            "behavior_graph_id": behavior_summary.get("graph_id", "-"),
            "risk_summary": risk_summary,
            "ai_summary": ai_summary,
            "diagnostics": diagnostics,
        }
        return {
            "launch_candidate_id": stable_id("launch-candidate", basis),
            "generated_at": safe_text(generated_at),
            "status": _status_from_diagnostics(diagnostics),
            "config_summary": config_summary,
            "startup_summary": startup_summary,
            "packet_intelligence_summary": packet_summary,
            "behavior_graph_summary": behavior_summary,
            "risk_summary": risk_summary,
            "ai_summary": ai_summary,
            "diagnostics": diagnostics,
            "cache": {
                "packet_summary_entries": len(self._packet_summary_cache),
            },
        }

    def _packet_intelligence_summary(self, **kwargs: Any) -> Dict[str, Any]:
        fingerprint = stable_id("packet-input", _fingerprint_kwargs(kwargs))
        cached = self._packet_summary_cache.get(fingerprint)
        if cached is not None:
            self.cache_hits += 1
            return cached
        self.cache_misses += 1
        summary = PacketIntelligenceEngine().summarize(**kwargs)
        self._packet_summary_cache[fingerprint] = summary
        return summary


def build_launch_candidate_summary(**kwargs: Any) -> Dict[str, Any]:
    return LaunchCandidateStabilizer().build_summary(**kwargs)


def deterministic_launch_candidate_json(summary: Dict[str, Any]) -> str:
    return stable_json(safe_metadata(summary))


def _fingerprint_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    for key in sorted(kwargs):
        value = kwargs[key]
        if value is None:
            result[key] = []
        elif isinstance(value, (list, tuple)):
            normalized_items = [
                safe_metadata(item.to_dict() if hasattr(item, "to_dict") else dict(item or {}))
                for item in value
            ]
            result[key] = sorted(normalized_items, key=lambda item: stable_json(item))
        elif isinstance(value, dict):
            result[key] = safe_metadata(value)
        else:
            result[key] = safe_text(value)
    return result


def _behavior_graph_summary(
    observation: Dict[str, Any] | None,
    *,
    classification_model: Dict[str, Any] | None,
    learning_profile: Dict[str, Any] | None,
    generated_at: str,
) -> Dict[str, Any]:
    graph = build_behavior_graph_model(
        safe_metadata(observation or {}),
        classification_model=safe_metadata(classification_model or {}),
        learning_profile=safe_metadata(learning_profile or {}),
        generated_at=generated_at,
    )
    return {
        "graph_id": graph.get("graph_id", "-"),
        "node_count": safe_int(graph.get("node_count"), len(graph.get("nodes") or [])),
        "edge_count": safe_int(graph.get("edge_count"), len(graph.get("edges") or [])),
        "relationship_count": safe_int(graph.get("relationship_count"), len(graph.get("relationships") or [])),
        "cluster_count": safe_int(graph.get("cluster_count"), len(graph.get("clusters") or [])),
        "primary_cluster_risk": safe_text(graph.get("primary_cluster_risk")),
        "behavioral_decision_category": safe_text(graph.get("behavioral_decision_category")),
    }


def _risk_summary(risk_cards: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = sorted([safe_metadata(dict(row or {})) for row in risk_cards], key=lambda row: (-safe_float(row.get("risk_score")), safe_text(row)))
    top = rows[0] if rows else {}
    return {
        "risk_count": len(rows),
        "highest_risk_score": safe_float(top.get("risk_score")) if top else 0.0,
        "highest_risk_label": safe_text(top.get("title") or top.get("label")),
        "risk_ids": [safe_text(row.get("card_id") or row.get("id")) for row in rows if safe_text(row.get("card_id") or row.get("id")) != "-"],
    }


def _ai_summary(ai_summaries: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = sorted([safe_metadata(dict(row or {})) for row in ai_summaries], key=lambda row: (safe_text(row.get("summary_id") or row.get("id")), safe_text(row)))
    confidence_values = [safe_float(row.get("confidence")) for row in rows if "confidence" in row]
    return {
        "ai_summary_count": len(rows),
        "average_confidence": round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0,
        "summary_ids": [safe_text(row.get("summary_id") or row.get("id")) for row in rows if safe_text(row.get("summary_id") or row.get("id")) != "-"],
    }


def _diagnostics(
    *,
    config_summary: Dict[str, Any],
    startup_summary: Dict[str, Any],
    packet_summary: Dict[str, Any],
    behavior_summary: Dict[str, Any],
    risk_summary: Dict[str, Any],
    ai_summary: Dict[str, Any],
) -> List[str]:
    diagnostics = set(config_summary.get("diagnostics", []))
    if startup_summary.get("missing_count"):
        diagnostics.add("startup_paths_missing")
    if not safe_int(packet_summary.get("packet_count")):
        diagnostics.add("empty_packet_state")
    if behavior_summary.get("graph_id") in {"", "-"}:
        diagnostics.add("empty_behavior_graph_state")
    if not safe_int(risk_summary.get("risk_count")):
        diagnostics.add("empty_risk_state")
    if not safe_int(ai_summary.get("ai_summary_count")):
        diagnostics.add("empty_ai_summary_state")
    return sorted(diagnostics)


def _status_from_diagnostics(diagnostics: List[str]) -> str:
    if not diagnostics:
        return "ready"
    blocking = {"startup_paths_missing"}
    if blocking.intersection(diagnostics):
        return "review"
    return "ready_with_empty_states"


def _disabled_summary(reason: str) -> Dict[str, Any]:
    return {"status": "disabled", "reason": reason}
