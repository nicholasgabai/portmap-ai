import json
import re
import zipfile

from core_engine.export import (
    build_operational_export_bundle,
    contains_private_identifiers,
    export_operational_bundle_json,
    redact_operational_record,
    validate_placeholder_safe,
    write_operational_export_archive,
    write_operational_export_bundle,
)
from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.runtime.runtime_state import RuntimeState
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from core_engine.topology.snapshots import build_topology_snapshot


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "export.db"))


def _snapshot(label="snapshot"):
    return build_topology_snapshot(
        assets=[
            {"asset_id": "asset-alpha", "label": "Asset Alpha", "category": "workload", "confidence": 0.9},
            {"asset_id": "asset-beta", "label": "Asset Beta", "category": "service", "confidence": 0.8},
        ],
        services=[{"asset_id": "asset-alpha", "service": "https", "port": 443}],
        topology_edges=[
            {
                "edge_id": "edge-alpha-beta",
                "source_asset": "asset-alpha",
                "target_asset": "asset-beta",
                "relationship_type": "service_dependency",
                "service_label": "https",
            }
        ],
        label=label,
        observed_at="2026-01-01T00:00:00+00:00",
    )


def _review_store(repository):
    store = PersistentReviewStore(repository)
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory findings.",
        now="2026-01-01T00:00:00+00:00",
    )
    review = build_review_record(
        policy=policy,
        source_ref="finding:finding-sample",
        category="policy_review_required",
        severity="high",
        title="Sample Review",
        summary="Sample review summary.",
        now="2026-01-01T00:00:00+00:00",
    )
    store.add_review(review)
    store.update_status(review.review_id, "approved", reviewed_by="operator-sample", now="2026-01-02T00:00:00+00:00")
    return store


def test_build_operational_export_bundle_from_existing_repository(tmp_path):
    repository = _repository(tmp_path)
    snapshot = _snapshot()
    repository.insert_snapshot(snapshot)
    repository.insert_topology_edge({"edge_id": "edge-extra", "src": "asset-beta", "dst": "asset-alpha", "protocol": "sample"})
    repository.insert_finding({"finding_id": "finding-sample", "finding_type": "sample_finding", "severity": "medium"})
    review_store = _review_store(repository)
    state = RuntimeState()
    state.mark_started(1.0)

    bundle = build_operational_export_bundle(
        repository=repository,
        review_store=review_store,
        runtime_state=state,
        diagnostics=[{"diagnostic_id": "diagnostic-sample", "diagnostic_type": "schema_validation", "status": "ok"}],
        label="sample-export",
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert bundle["manifest"]["bundle_type"] == "operational_evidence_export"
    assert bundle["manifest"]["record_counts"]["snapshots"] == 1
    assert bundle["manifest"]["record_counts"]["findings"] == 1
    assert bundle["manifest"]["record_counts"]["review_records"] == 2
    assert bundle["manifest"]["record_counts"]["runtime_summaries"] == 1
    assert bundle["manifest"]["digest"].startswith("sha256:")
    assert bundle["topology"]["summary"]["node_count"] == 2
    assert bundle["raw_payload_stored"] is False
    assert bundle["automatic_changes"] is False


def test_operational_export_json_is_deterministic_for_sanitized_input(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_snapshot(_snapshot())

    first = build_operational_export_bundle(
        repository=repository,
        label="sample-export",
        generated_at="2026-01-03T00:00:00+00:00",
    )
    second = build_operational_export_bundle(
        repository=repository,
        label="sample-export",
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert first["manifest"]["digest"] == second["manifest"]["digest"]
    assert export_operational_bundle_json(first) == export_operational_bundle_json(second)


def test_redaction_and_placeholder_validation_remove_private_identifiers():
    secret_key = "api_" + "token"
    payload = {
        "asset": ".".join(["192", "168", "1", "10"]),
        "mac": ":".join(["aa", "bb", "cc", "dd", "ee", "ff"]),
        "path": "/" + "Users" + "/sample/local.txt",
        secret_key: "sample-" + "secret-" + "value",
    }

    assert contains_private_identifiers(payload) is True
    redacted = redact_operational_record(payload)
    validation = validate_placeholder_safe(redacted)

    assert validation["ok"] is True
    assert redacted["asset"] == "<redacted-ip>"
    assert redacted["mac"] == "<redacted-mac>"
    assert redacted["path"] == "<redacted-path>"
    assert str(redacted[secret_key]).startswith("<redacted:")


def test_write_json_bundle_and_archive_to_operator_path(tmp_path):
    bundle = build_operational_export_bundle(
        snapshots=[_snapshot()],
        runtime_summary={"status": "ok", "scheduler_status": "sample"},
        generated_at="2026-01-03T00:00:00+00:00",
    )
    json_result = write_operational_export_bundle(tmp_path / "bundle.json", bundle)
    archive_result = write_operational_export_archive(tmp_path / "bundle.zip", bundle)

    assert json_result["status"] == "written"
    assert json_result["path_stored"] is False
    assert archive_result["archive_name"] == "bundle.zip"
    assert archive_result["path_stored"] is False
    with zipfile.ZipFile(tmp_path / "bundle.zip") as archive:
        assert sorted(archive.namelist()) == ["bundle.json", "manifest.json"]
        assert json.loads(archive.read("manifest.json"))["digest"] == bundle["manifest"]["digest"]


def test_bundle_output_does_not_contain_private_identifiers(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_snapshot(_snapshot())
    bundle = build_operational_export_bundle(
        repository=repository,
        findings=[
            {
                "finding_id": "finding-private-sample",
                "finding_type": "sample",
                "severity": "medium",
                "evidence": {"host": ".".join(["10", "1", "2", "3"]), "path": "/" + "home" + "/sample/data"},
            }
        ],
        generated_at="2026-01-03T00:00:00+00:00",
    )
    payload = export_operational_bundle_json(bundle)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
