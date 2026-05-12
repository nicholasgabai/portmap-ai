import json

import pytest

from core_engine.nodes import (
    NodeIdentityError,
    NodeRegistry,
    create_node_capabilities,
    create_node_identity,
    generate_node_id,
    load_node_identity,
    node_identity_fingerprint,
    save_node_identity,
)
from core_engine.nodes.capabilities import NodeCapabilitiesError
from core_engine.nodes.registry import NodeRegistryError


def _identity():
    return create_node_identity(role="worker", node_id="worker-sample", now="2026-01-01T00:00:00+00:00")


def _capabilities(node_id="worker-sample", role="worker"):
    return create_node_capabilities(
        node_id=node_id,
        role=role,
        platform="Linux",
        architecture="aarch64",
        supported_features=["visibility", "events"],
        runtime_version="sample-version",
        metadata={"profile": "sample"},
    )


def test_identity_creation_save_and_load(tmp_path):
    identity = _identity()
    path = tmp_path / "identity" / "node.json"

    save_node_identity(identity, path, updated_at="2026-01-01T00:05:00+00:00")
    loaded = load_node_identity(path)

    assert path.exists()
    assert loaded.node_id == "worker-sample"
    assert loaded.role == "worker"
    assert loaded.created_at == "2026-01-01T00:00:00+00:00"
    assert loaded.updated_at == "2026-01-01T00:05:00+00:00"
    assert loaded.fingerprint == identity.fingerprint
    assert loaded.local_only is True


def test_generate_node_id_and_stable_fingerprint():
    node_id = generate_node_id("worker")
    identity = _identity()
    updated = create_node_identity(role="worker", node_id="worker-sample", now="2026-01-01T00:00:00+00:00")
    updated.updated_at = "2026-01-02T00:00:00+00:00"

    assert node_id.startswith("worker-")
    assert node_identity_fingerprint(identity) == node_identity_fingerprint(updated)


def test_malformed_identity_is_rejected(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"node_id": "", "role": "worker"}), encoding="utf-8")

    with pytest.raises(NodeIdentityError):
        load_node_identity(bad_path)

    identity = _identity().to_dict()
    identity["fingerprint"] = "bad-fingerprint"
    with pytest.raises(NodeIdentityError):
        create_node_identity(role="", node_id="worker-sample")
    with pytest.raises(NodeIdentityError):
        load_node_identity(_write_json(tmp_path / "bad-fingerprint.json", identity))


def test_capability_record_creation_and_validation():
    capabilities = _capabilities()

    assert capabilities.node_id == "worker-sample"
    assert capabilities.role == "worker"
    assert capabilities.supported_features == ["visibility", "events"]
    assert capabilities.local_only is True
    assert capabilities.to_dict()["architecture"] == "aarch64"

    with pytest.raises(NodeCapabilitiesError):
        create_node_capabilities(node_id="node", role="worker", platform="Linux", architecture="x86_64", supported_features=["ok", 5])


def test_node_registration_and_summary():
    registry = NodeRegistry()
    entry = registry.register_node(_identity(), _capabilities(), now="2026-01-01T00:00:00+00:00")

    assert entry.lifecycle_state == "registered"
    assert registry.get_node("worker-sample") == entry
    summary = registry.summarize_nodes()
    assert summary["local_only"] is True
    assert summary["automatic_changes"] is False
    assert summary["by_state"]["registered"] == 1
    assert summary["nodes"][0]["supported_features"] == ["visibility", "events"]


def test_heartbeat_updates_metadata_and_online_state():
    registry = NodeRegistry()
    registry.register_node(_identity(), _capabilities(), now="2026-01-01T00:00:00+00:00")

    first = registry.update_heartbeat(
        "worker-sample",
        now="2026-01-01T00:01:00+00:00",
        status_message="Sample heartbeat",
        health_status="ok",
        scheduler_status="running",
        event_queue_depth=2,
    )
    second = registry.update_heartbeat("worker-sample", now="2026-01-01T00:02:00+00:00", health_status="ok")

    assert first.lifecycle_state == "online"
    assert second.heartbeat.heartbeat_count == 2
    assert second.heartbeat.last_seen_at == "2026-01-01T00:02:00+00:00"
    assert registry.summarize_nodes()["by_state"]["online"] == 1


def test_stale_and_offline_transitions():
    registry = NodeRegistry()
    registry.register_node(_identity(), _capabilities(), now="2026-01-01T00:00:00+00:00")
    registry.update_heartbeat("worker-sample", now="2026-01-01T00:00:00+00:00")

    stale = registry.mark_stale_nodes(now="2026-01-01T00:05:00+00:00", stale_after_seconds=60, offline_after_seconds=600)
    assert [entry.lifecycle_state for entry in stale] == ["stale"]
    offline = registry.mark_stale_nodes(now="2026-01-01T00:11:00+00:00", stale_after_seconds=60, offline_after_seconds=600)

    assert [entry.lifecycle_state for entry in offline] == ["offline"]
    assert registry.get_node("worker-sample").lifecycle_state == "offline"


def test_removal_behavior():
    registry = NodeRegistry()
    registry.register_node(_identity(), _capabilities(), now="2026-01-01T00:00:00+00:00")

    assert registry.remove_node("worker-sample", now="2026-01-01T00:03:00+00:00") is True
    assert registry.remove_node("missing") is False
    assert registry.list_nodes() == []
    removed = registry.get_node("worker-sample")
    assert removed.lifecycle_state == "removed"
    assert removed.removed_at == "2026-01-01T00:03:00+00:00"
    assert registry.summarize_nodes(include_removed=True)["by_state"]["removed"] == 1
    with pytest.raises(NodeRegistryError):
        registry.update_heartbeat("worker-sample", now="2026-01-01T00:04:00+00:00")


def test_registry_rejects_mismatched_identity_and_capabilities():
    registry = NodeRegistry()
    with pytest.raises(NodeRegistryError):
        registry.register_node(_identity(), _capabilities(node_id="other-node"))


def _write_json(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
