import copy
import json
import logging
from types import SimpleNamespace
from datetime import datetime

import pytest

from core_engine import dispatcher, worker_node
from core_engine.api import create_local_api_app
from core_engine.attribution import build_probabilistic_application_model
from core_engine.flows.session_tracking import normalize_socket_observations
from core_engine.history.snapshot_store import rotate_historical_snapshots
from core_engine.history.snapshots import build_historical_snapshot
from core_engine.modules.flow_tracker import build_flow_report
from core_engine.modules.scanner import normalize_scan_snapshot
from core_engine.observation_identity import observation_identity
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge
from core_engine.storage import LocalStorageRepository, SQLiteStore
from core_engine.time_utils import AmbiguousTimestampError, observation_timestamps, parse_utc_instant
from gui import app as gui_app


EVENT = "2026-07-05T02:19:22Z"
INGESTED = "2026-07-05T02:19:52Z"


def socket_row(**changes):
    row = {
        "node_id": "worker-a", "local": "192.0.2.10:51515", "remote": "198.51.100.20:22",
        "port": 51515, "protocol": "TCP", "status": "ESTABLISHED", "service_name": "ssh",
        "program": "sshd", "source_mode": "live", "timestamp": EVENT,
    }
    row.update(changes)
    return row


@pytest.mark.parametrize("changes", [
    {"node_id": "worker-b"}, {"remote": "198.51.100.21:22"},
    {"local": "192.0.2.11:51515"}, {"protocol": "UDP"}, {"direction": "inbound"},
])
def test_independent_connections_never_share_canonical_identity(changes):
    first = observation_identity(socket_row())
    second = observation_identity(socket_row(**changes))
    for key in ("observation_id", "session_id", "flow_key"):
        assert first[key] != second[key]
    sessions = normalize_socket_observations([socket_row(), socket_row(**changes)])
    assert len(sessions) == 2


def test_bridge_matches_the_full_endpoint_identity_not_just_ports():
    rows = [socket_row(ingested_at=INGESTED), socket_row(remote="198.51.100.21:22", ingested_at=INGESTED)]
    original = copy.deepcopy(rows)
    report = build_milestone_v_runtime_bridge(rows, node_id="worker-a", generated_at=INGESTED)
    assert rows == original
    pairs = report["api_status"]["flows"]["flow_pairs"]
    assert len(pairs) == 2
    for observation in report["observations"]:
        pair = next(row for row in pairs if row["session_id"] == observation["session_id"])
        assert pair["remote_address"] == observation["remote_address"]
        assert pair["observation_id"] == observation["observation_id"]
    correlations = report["api_status"]["metadata_correlations"]["metadata_correlations"]
    assert len({row["observation_id"] for row in correlations}) == 2
    processes = report["api_status"]["process_correlations"]["process_correlations"]
    for row in pairs + correlations + processes:
        assert row["event_timestamp"] == EVENT
        assert row["ingested_at"] == INGESTED
    attributions = report["api_status"]["attribution"]["attributions"]
    assert {row["session_id"] for row in attributions} == {row["session_id"] for row in pairs}


def test_ipv6_compression_scope_and_ipv4_are_distinct():
    first = socket_row(local="[2001:db8::10]:51515", remote="[2001:db8::20]:22")
    equivalent = socket_row(local="[2001:0db8:0:0:0:0:0:10]:51515", remote="[2001:db8::20]:22")
    assert observation_identity(first) == observation_identity(equivalent)
    assert observation_identity(first)["address_family"] == "ipv6"
    assert observation_identity(first)["session_id"] != observation_identity(socket_row())["session_id"]
    scoped = observation_identity(socket_row(local="[fe80::10%eth0]:51515", remote="[fe80::20%eth0]:22"))
    other = observation_identity(socket_row(local="[fe80::10%eth1]:51515", remote="[fe80::20%eth1]:22"))
    assert scoped["session_id"] != other["session_id"]
    report = build_milestone_v_runtime_bridge([first], node_id="worker-a", generated_at=INGESTED)
    assert report["flow_events"][0]["src_ip"] == "2001:db8::10"
    assert report["flow_events"][0]["dst_ip"] == "2001:db8::20"


def test_listener_has_no_flow_even_if_stale_remote_metadata_exists():
    row = socket_row(status="LISTEN", port=22, local="192.0.2.10:22", flow_key="stale-flow")
    report = build_milestone_v_runtime_bridge([row], node_id="worker-a", generated_at=INGESTED)
    observation = report["observations"][0]
    assert observation["flow_key"] == ""
    assert observation["identity_scope"] == "listener"
    assert report["flow_events"] == []
    finding = gui_app._active_risk_finding_rows([], [observation])[0]
    assert dict(gui_app._finding_detail_rows(finding))["Flow Key"] == "not applicable"


def test_repeated_poll_is_a_new_observation_of_the_same_session():
    first = observation_identity(socket_row())
    repeated = observation_identity(socket_row())
    later = observation_identity(socket_row(timestamp=INGESTED))
    assert first == repeated
    assert first["session_id"] == later["session_id"]
    assert first["flow_key"] == later["flow_key"]
    assert first["observation_id"] != later["observation_id"]
    assert len(normalize_scan_snapshot([socket_row(), socket_row()])) == 1


@pytest.mark.parametrize("event", ["2026-07-04T22:19:22-04:00", "2026-07-05T04:19:22+02:00", EVENT])
def test_timezone_and_date_rollover_preserve_identity_and_instants(event):
    assert observation_identity(socket_row(timestamp=event)) == observation_identity(socket_row())
    times = observation_timestamps({"timestamp": event}, ingested_at=INGESTED, strict=True)
    assert times["event_timestamp"] == times["timestamp"] == EVENT
    assert times["ingested_at"] == INGESTED


def test_legacy_ambiguous_or_missing_event_time_never_becomes_receipt_time(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: INGESTED)
    for timestamp in ("2026-07-04 22:19:22", None):
        row = socket_row(timestamp=timestamp)
        dispatcher.dispatch_alert({"node_id": "worker-a", "ports": [row], "timestamp": timestamp})
        event = json.loads(path.read_text().splitlines()[-1])
        assert event["event_timestamp"] == timestamp
        assert event["ingested_at"] == INGESTED
        assert event["observations"][0]["event_timestamp"] == timestamp
        assert event["flows"][0]["event_timestamp"] == timestamp
        if timestamp is None:
            assert event["observations"][0]["observation_id"] == ""
            assert event["observations"][0]["timestamp"] is None
        assert event["timestamp_status"] == ("ambiguous_legacy" if timestamp else "unavailable")
    with pytest.raises(AmbiguousTimestampError):
        observation_timestamps({"timestamp": "2026-07-04 22:19:22"}, strict=True)
    with pytest.raises(AmbiguousTimestampError):
        observation_timestamps({"timestamp": datetime(2026, 7, 4, 22, 19, 22)}, strict=True)


def test_worker_master_sqlite_ai_api_tui_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(worker_node, "utc_now_iso", lambda: EVENT)
    def score(row, use_ml=False):
        row["ai_provider"] = "heuristic"
        return 0.4
    monkeypatch.setattr(worker_node, "get_score", score)
    monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: INGESTED)
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    payload = worker_node.build_payload("worker-a", [socket_row(timestamp="2026-07-04T22:19:22-04:00")], logging.getLogger("test"), False)
    before = copy.deepcopy(payload)
    # Use the actual transport codec without opening sockets.
    from core_engine.telemetry_framing import decode_json_frame, encode_json_frame
    dispatcher.dispatch_alert(decode_json_frame(encode_json_frame(payload)))
    assert payload == before
    event = json.loads(path.read_text().splitlines()[0])
    observation = event["observations"][0]
    for key in ("observation_id", "session_id", "flow_key", "event_timestamp"):
        assert observation[key] == payload["ports"][0][key]
    assert observation["ingested_at"] == event["ingested_at"] == INGESTED
    record = {**observation, "event_id": observation["observation_id"], "event_type": "network_observation", "severity": "low", "source": "worker", "message": "Socket metadata observed"}
    db_path = tmp_path / "evidence.sqlite"
    with SQLiteStore(db_path) as store:
        repository = LocalStorageRepository(store)
        repository.insert_event(record)
        repository.insert_finding(record)
    with SQLiteStore(db_path) as store:
        repository = LocalStorageRepository(store)
        status, response = create_local_api_app(repository=repository).get("/events")
        assert status == 200
        persisted = response["items"][0]
        assert persisted == record
        finding = repository.list_findings()[0]
        assert all(finding[key] == value for key, value in record.items())
        json.dumps(response)
    model = build_probabilistic_application_model(persisted, generated_at=INGESTED)
    for context in (model["observation_context"], model["learning_profile_history"]["observation_records"][0]):
        for key in ("observation_id", "session_id", "flow_key", "event_timestamp", "ingested_at"):
            assert context[key] == persisted[key]
    assert model["behavior_graph"]["summary"]["event_timestamp"] == EVENT
    assert model["behavior_graph"]["investigation_chains"][0]["related_observation"] == persisted["observation_id"]
    scans = gui_app._scan_rows_from_telemetry([event])
    assert scans[0]["observation_id"] == persisted["observation_id"]
    risk = gui_app._active_risk_finding_rows([], scans)[0]
    ai = gui_app._ai_provider_model_rows(gui_app._ai_events_from_sources(scan_results=scans))[0]
    for details in (dict(gui_app._finding_detail_rows(risk)), dict(gui_app._ai_detail_rows(ai))):
        assert details["Observation ID"] == persisted["observation_id"]
        assert details["Event Time UTC"] == "2026-07-05 02:19:22 UTC"
        assert details["Ingested At UTC"] == "2026-07-05 02:19:52 UTC"
    assert model["automated_action"] is False
    assert event["flows"][0]["pcap_generated"] is False


def test_flow_aggregation_does_not_combine_workers_or_lose_duration():
    events = []
    for node in ("worker-a", "worker-b"):
        for timestamp in (EVENT, INGESTED):
            report = build_milestone_v_runtime_bridge([socket_row(timestamp=timestamp)], node_id=node, generated_at=INGESTED)
            events.extend(report["flow_events"])
    flows = build_flow_report(events)["flows"]
    assert len(flows) == 2
    assert {flow["node_id"] for flow in flows} == {"worker-a", "worker-b"}
    for row in gui_app._packet_activity_rows(flows):
        assert dict(gui_app._packet_detail_rows(row))["Conversation Duration"] == "30s"


def test_sqlite_legacy_records_are_preserved_verbatim(tmp_path):
    legacy = {"event_id": "legacy", "timestamp": "2026-07-04 22:19:22", "event_type": "network", "severity": "low", "source": "legacy", "message": "Legacy metadata"}
    with SQLiteStore(tmp_path / "legacy.sqlite") as store:
        repository = LocalStorageRepository(store)
        repository.insert_event(legacy)
        assert create_local_api_app(repository=repository).get("/events")[1]["items"] == [legacy]
    assert "timezone ambiguous" in gui_app._format_timestamp(legacy["timestamp"])


def test_current_snapshot_uses_ingestion_order_but_preserves_event_time():
    earlier = {"node_id": "worker-a", "timestamp": INGESTED, "ingested_at": EVENT, "ports_sample": [socket_row()]}
    later = {"node_id": "worker-a", "timestamp": EVENT, "ingested_at": INGESTED, "ports_sample": [socket_row(remote="198.51.100.21:22")]}
    assert gui_app._scan_rows_from_telemetry([later, earlier])[0]["remote"] == "198.51.100.21:22"


def test_utc_header_and_risk_history_label_the_same_instant():
    assert str(gui_app.UTCHeaderClock().render()).endswith(" UTC")
    events = [socket_row(timestamp="2026-07-04T22:19:22-04:00")]
    history = next(iter(gui_app._risk_finding_history(events).values()))
    assert history["first_seen"] == "2026-07-05 02:19:22 UTC"
    assert parse_utc_instant(EVENT) is not None


def test_snapshot_retention_orders_aware_instants_without_rewriting_legacy():
    old = build_historical_snapshot({}, generated_at="2026-07-05T04:19:22+02:00")
    new = build_historical_snapshot({}, generated_at="2026-07-05T02:19:52Z")
    legacy = build_historical_snapshot({}, generated_at="2026-07-04 22:19:22")
    result = rotate_historical_snapshots([new, legacy, old], max_snapshots=2)
    assert result["retained_snapshot_ids"] == [old["snapshot_id"], new["snapshot_id"]]
    assert old["snapshot_timestamp"] == "2026-07-05T04:19:22+02:00"
    assert legacy["snapshot_timestamp"] == "2026-07-04 22:19:22"


def test_risk_decision_retains_the_selected_observation_time_and_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatcher, "MASTER_LOG", tmp_path / "events.jsonl")
    risk_path = tmp_path / "risk.jsonl"
    monkeypatch.setattr(dispatcher, "REMEDIATION_LOG", risk_path)
    monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: INGESTED)
    monkeypatch.setattr(dispatcher, "record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(dispatcher, "handle_remediation", lambda *args: SimpleNamespace(action="prompt_operator", reason="metadata review", score=0.8, mode="prompt"))
    dispatcher.dispatch_alert({"node_id": "worker-a", "timestamp": INGESTED, "ports": [socket_row(score=0.8)]}, settings={})
    event = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])
    risk = json.loads(risk_path.read_text().splitlines()[0])
    for key in ("observation_id", "flow_key", "session_id", "event_timestamp", "ingested_at"):
        assert risk[key] == event["observations"][0][key]
    assert risk["timestamp"] == risk["event_timestamp"] == EVENT
    assert risk["dry_run"] is True


def test_legacy_supplied_ids_do_not_merge_distinct_nodes_or_peers_in_ai():
    events = [
        socket_row(observation_id="legacy-id", ai_provider="heuristic"),
        socket_row(observation_id="legacy-id", ai_provider="heuristic", node_id="worker-b"),
        socket_row(observation_id="legacy-id", ai_provider="heuristic", remote_address="198.51.100.21"),
    ]
    events[0]["local_address"] = events[1]["local_address"] = events[2]["local_address"] = "192.0.2.10"
    events[0]["remote_address"] = events[1]["remote_address"] = "198.51.100.20"
    rows = gui_app._ai_provider_model_rows(events)
    assert len(rows) == 3
    assert len({row["key"] for row in rows}) == 3
    assert {row["observation_id"] for row in rows} == {"legacy-id"}


def test_incomplete_legacy_socket_can_infer_direction_without_inventing_endpoints():
    row = {"local_port": 22, "remote_port": 51515, "protocol": "tcp", "transport_state": "established", "source_mode": "live"}
    record = normalize_socket_observations([row], generated_at=EVENT)[0]
    assert record["flow_direction"] == "inbound"
    assert record["identity_scope"] == "socket"
    assert record["local_address"] == record["remote_address"] == record["flow_key"] == ""


def test_api_normalizes_new_time_fields_without_mutating_the_provider():
    source = {"event_timestamp": "2026-07-04T22:19:22-04:00", "ingested_at": "2026-07-05T04:19:52+02:00"}
    original = dict(source)
    _, response = create_local_api_app(events=[source]).get("/events")
    assert source == original
    assert response["items"][0]["event_timestamp"] == EVENT
    assert response["items"][0]["ingested_at"] == INGESTED


def test_packet_status_orders_raw_event_instants_and_ai_ignores_receipt_time_for_sorting():
    flows = [
        {"first_seen": "2026-07-05T04:19:22+02:00", "last_seen": "2026-07-05T04:19:22+02:00"},
        {"first_seen": "2026-07-05T02:19:52Z", "last_seen": "2026-07-05T02:19:52Z"},
    ]
    rows = gui_app._packet_activity_rows(flows)
    assert gui_app._packet_status_table_row(list(reversed(rows)))["updated"] == "2026-07-05 02:19:52 UTC"
    assert gui_app._ai_raw_time({"event_timestamp": EVENT, "created_at": INGESTED}) == EVENT
    assert gui_app._ai_raw_time({"event_timestamp": None, "timestamp": INGESTED}) is None


def test_mixed_worker_bridge_batch_retains_both_observed_conversations():
    report = build_milestone_v_runtime_bridge([socket_row(), socket_row(node_id="worker-b")], generated_at=INGESTED)
    assert {row["node_id"] for row in report["flow_events"]} == {"worker-a", "worker-b"}
    assert len({row["observation_id"] for row in report["flow_events"]}) == 2
    assert gui_app._packet_endpoint_label({"ip": "2001:db8::10", "port": 22}) == "[2001:db8::10]:22"


def test_enriched_observation_persistence_remains_metadata_only():
    report = build_milestone_v_runtime_bridge(
        [socket_row(payload="excluded-body", credentials="excluded-secret", metadata={"token": "excluded-secret"})],
        node_id="worker-a", generated_at=INGESTED,
    )
    assert "excluded-body" not in json.dumps(report)
    assert "excluded-secret" not in json.dumps(report)


def test_structured_endpoint_metadata_survives_bridge_allowlisting():
    row = socket_row(src_ip="192.0.2.10", src_port=51515, dst_ip="198.51.100.20", dst_port=22)
    row.pop("local")
    row.pop("remote")
    report = build_milestone_v_runtime_bridge([row], node_id="worker-a", generated_at=INGESTED)
    observation = report["observations"][0]
    assert observation["local_address"] == "192.0.2.10"
    assert observation["remote_address"] == "198.51.100.20"
    assert observation["address_family"] == "ipv4"
    assert observation["flow_key"]
    assert report["flow_events"][0]["dst_port"] == 22


def test_bridge_failure_does_not_publish_raw_rows_as_canonical_observations(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    def fail(*args, **kwargs):
        raise ValueError("metadata reconstruction unavailable")
    monkeypatch.setattr(dispatcher, "build_milestone_v_runtime_bridge", fail)
    dispatcher.dispatch_alert({"node_id": "worker-a", "ports": [socket_row()]})
    event = json.loads(path.read_text().splitlines()[0])
    assert event["observations"] == event["flows"] == []
    assert event["ports_sample"][0]["remote"] == "198.51.100.20:22"
    assert event["milestone_v"]["error_summary"] == "metadata reconstruction unavailable"


@pytest.mark.parametrize("alias", ["event_id", "packet_id", "record_id"])
def test_legacy_identity_aliases_are_preserved(alias):
    row = socket_row(**{alias: "original-observation", "flow_id": "original-flow"})
    identity = observation_identity(row)
    assert identity["observation_id"] == "original-observation"
    assert identity["flow_key"] == "original-flow"
    report = build_milestone_v_runtime_bridge([row], generated_at=INGESTED)
    assert report["observations"][0]["observation_id"] == "original-observation"
    assert report["flow_events"][0]["flow_key"] == "original-flow"


def test_learning_history_records_event_time_not_analysis_time():
    row = {**socket_row(), **observation_timestamps(socket_row(), ingested_at=INGESTED)}
    model = build_probabilistic_application_model(row, generated_at=INGESTED)
    history = model["learning_profile_history"]
    assert history["observation_records"][0]["observed_at"] == EVENT
    assert history["observation_timestamps"] == [EVENT]
    assert model["learning_profile"]["confidence_history"][0]["observed_at"] == EVENT


def test_missing_event_time_does_not_create_duration_history_or_ai_observation_id():
    row = socket_row(event_timestamp=None, timestamp=INGESTED, ingested_at=INGESTED)
    record = normalize_socket_observations([row], generated_at=INGESTED)[0]
    assert record["observed_timestamps"] == []
    assert record["session_duration_preview"]["first_seen"] == ""
    model = build_probabilistic_application_model({**row, **observation_identity(row)}, generated_at=INGESTED)
    assert model["observation_context"]["observation_id"] == "-"
    assert model["learning_profile_history"]["observation_records"][0]["observed_at"] == ""
    assert model["learning_profile_history"]["observation_timestamps"] == []


def test_session_aggregate_representative_is_latest_sample_and_order_independent():
    rows = [socket_row(), socket_row(timestamp=INGESTED)]
    forward = normalize_socket_observations(rows, generated_at=INGESTED)
    reverse = normalize_socket_observations(list(reversed(rows)), generated_at=INGESTED)
    assert forward == reverse
    session = forward[0]
    assert session["observation_id"] == observation_identity(rows[1])["observation_id"]
    assert session["event_timestamp"] == INGESTED
    assert session["session_duration_preview"]["duration_seconds"] == 30
    from core_engine.runtime.milestone_v_bridge import _enrich_socket_identities
    samples = [{**row, **observation_identity(row)} for row in rows]
    enriched = _enrich_socket_identities(socket_rows=samples, sessions=forward, flow_pairs=[])
    assert [row["observation_id"] for row in enriched] == [row["observation_id"] for row in samples]


def test_reused_legacy_ids_are_scoped_by_full_endpoints_in_risk_and_ai():
    rows = []
    for port in (51515, 51516):
        raw = socket_row(local=f"192.0.2.10:{port}", port=port, ai_provider="heuristic")
        rows.append({**raw, **observation_identity(raw), "observation_id": "legacy", "session_id": "legacy-session"})
    risk = gui_app._active_risk_finding_rows([], rows)
    ai = gui_app._ai_provider_model_rows(rows)
    assert len({row["key"] for row in risk}) == 2
    assert len({row["identity"] for row in risk}) == 2
    assert len({row["key"] for row in ai}) == 2
    # Same local port and ID, different peer: risk keys cannot use only the visible service.
    rows[1] = {**rows[0], "remote_address": "198.51.100.21", "remote": "198.51.100.21:22"}
    risk = gui_app._active_risk_finding_rows([], rows)
    assert len({row["key"] for row in risk}) == 2
    assert len({row["identity"] for row in risk}) == 2


def test_sqlite_and_api_preserve_explicitly_unknown_event_time(tmp_path):
    row = {"event_id": "unknown-time", "event_type": "network", "severity": "low", "source": "legacy", "message": "No event time", "event_timestamp": None, "timestamp": INGESTED, "ingested_at": INGESTED}
    with SQLiteStore(tmp_path / "unknown.sqlite") as store:
        repository = LocalStorageRepository(store)
        repository.insert_event(row)
        item = create_local_api_app(repository=repository).get("/events")[1]["items"][0]
        assert item["event_timestamp"] is item["timestamp"] is None
        assert item["ingested_at"] == INGESTED
    assert row["timestamp"] == INGESTED


def test_packet_aggregation_keeps_socket_and_capture_contexts_separate():
    socket_event = build_milestone_v_runtime_bridge([socket_row()], generated_at=INGESTED)["flow_events"][0]
    capture_event = {**socket_event, "telemetry_source": "packet_metadata", "evidence_origin": "packet_metadata"}
    fixture_event = {**socket_event, "source_mode": "fixture"}
    flows = build_flow_report([socket_event, capture_event, fixture_event])["flows"]
    assert len(flows) == 3
    assert all(flow["event_count"] == 1 for flow in flows)


def test_sample_correlation_does_not_take_a_different_session_sample_time():
    from core_engine.flows.metadata_correlation import build_metadata_correlation_record
    sample = {**socket_row(), **observation_identity(socket_row()), **observation_timestamps(socket_row())}
    summary = normalize_socket_observations([socket_row(), socket_row(timestamp=INGESTED)], generated_at=INGESTED)[0]
    correlation = build_metadata_correlation_record(socket_observation=sample, reconstructed_session=summary, generated_at=INGESTED)
    assert correlation["observation_id"] == sample["observation_id"]
    assert correlation["event_timestamp"] == EVENT
    sample["event_timestamp"] = None
    correlation = build_metadata_correlation_record(socket_observation=sample, reconstructed_session=summary, generated_at=INGESTED)
    assert correlation["event_timestamp"] is None
