from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Iterable

from core_engine.config_loader import DATA_DIR, ensure_runtime_dirs


DEFAULT_CVE_CACHE = DATA_DIR / "cve_cache.json"


def default_cve_cache_path() -> Path:
    return DEFAULT_CVE_CACHE


def load_cve_cache(path: str | Path | None = None) -> dict[str, Any]:
    cache_path = Path(path).expanduser() if path else DEFAULT_CVE_CACHE
    if not cache_path.exists():
        return {
            "ok": True,
            "cache_path": str(cache_path),
            "updated_at": None,
            "records": [],
            "record_count": 0,
        }
    with open(cache_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("records") if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        records = []
    return {
        "ok": True,
        "cache_path": str(cache_path),
        "updated_at": payload.get("updated_at") if isinstance(payload, dict) else None,
        "metadata": payload.get("metadata", {}) if isinstance(payload, dict) else {},
        "records": [record for record in records if isinstance(record, dict)],
        "record_count": len([record for record in records if isinstance(record, dict)]),
    }


def save_cve_cache(
    records: Iterable[dict[str, Any]],
    *,
    path: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_runtime_dirs()
    cache_path = Path(path).expanduser() if path else DEFAULT_CVE_CACHE
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    merged = merge_cve_records([], records)
    payload = {
        "updated_at": datetime.now(UTC).isoformat(),
        "metadata": metadata or {},
        "records": merged,
    }
    with open(cache_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return {
        "ok": True,
        "cache_path": str(cache_path),
        "record_count": len(merged),
        "updated_at": payload["updated_at"],
    }


def merge_cve_records(
    existing: Iterable[dict[str, Any]],
    incoming: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for record in list(existing) + list(incoming):
        if not isinstance(record, dict):
            continue
        cve_id = str(record.get("id") or record.get("cve_id") or "").upper()
        if not cve_id:
            continue
        normalized = {**record, "id": cve_id}
        previous = by_id.get(cve_id, {})
        by_id[cve_id] = {**previous, **normalized}
    return [by_id[key] for key in sorted(by_id)]
