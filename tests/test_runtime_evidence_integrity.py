import copy
import json
import logging
from types import SimpleNamespace
from datetime import datetime
from zipfile import ZipFile

import pytest

from core_engine import dispatcher, worker_node
from core_engine.api import create_local_api_app
from core_engine.attribution import build_probabilistic_application_model
from core_engine.export import build_operational_export_bundle, export_operational_bundle_json
from core_engine.flows.session_tracking import normalize_socket_observations
from core_engine.history.snapshot_store import rotate_historical_snapshots
from core_engine.history.snapshots import build_historical_snapshot
from core_engine.modules.flow_tracker import build_flow_report
from core_engine.modules.scanner import normalize_scan_snapshot
from core_engine.observation_identity import observation_identity
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge
from core_engine.storage import LocalStorageRepository, SQLiteStore
from core_engine.storage.sqlite_store import StorageError
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


@pytest.mark.parametrize("changes", [
    pytest.param({}, id="tcp-ipv4"),
    pytest.param({"local": "[2001:db8::10]:51515", "remote": "[2001:db8::20]:22"}, id="tcp-ipv6"),
    pytest.param({"protocol": "UDP", "status": "NONE", "remote": "198.51.100.20:53", "service_name": "dns", "program": "resolver"}, id="connected-udp"),
    pytest.param({"local": "192.0.2.10:22", "port": 22, "remote": "-", "status": "LISTEN"}, id="listener"),
])
def test_worker_master_sqlite_ai_api_tui_round_trip(tmp_path, monkeypatch, changes):
    monkeypatch.setattr(worker_node, "utc_now_iso", lambda: EVENT)
    def score(row, use_ml=False):
        row["ai_provider"] = "heuristic"
        return 0.4
    monkeypatch.setattr(worker_node, "get_score", score)
    monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: INGESTED)
    path = tmp_path / "events.jsonl"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    payload = worker_node.build_payload("worker-a", [socket_row(timestamp="2026-07-04T22:19:22-04:00", **changes)], logging.getLogger("test"), False)
    before = copy.deepcopy(payload)
    # Use the actual transport codec without opening sockets.
    from core_engine.telemetry_framing import decode_json_frame, encode_json_frame
    dispatcher.dispatch_alert(decode_json_frame(encode_json_frame(payload)))
    assert payload == before
    event = json.loads(path.read_text().splitlines()[0])
    observation = event["observations"][0]
    identity_fields = ("observation_id", "session_id", "flow_key", "node_id", "local_address", "remote_address", "local_port", "remote_port", "address_family", "identity_scope", "evidence_origin", "event_timestamp")
    for key in identity_fields:
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
        bundle = build_operational_export_bundle(repository=repository, generated_at=INGESTED)
        exported = json.loads(export_operational_bundle_json(bundle))["findings"][0]
        for key in (*identity_fields, "ingested_at"):
            if key == "flow_key" and record[key]:
                assert exported[key].startswith("<redacted:")
            else:
                assert exported[key] == record[key]
        local_bundle = build_operational_export_bundle(repository=repository, generated_at=INGESTED, redact=False)
        local_export = json.loads(export_operational_bundle_json(local_bundle))["findings"][0]
        for key in (*identity_fields, "ingested_at"):
            assert local_export[key] == record[key]
        assert bundle["local_only"] is True
        assert bundle["raw_payload_stored"] is bundle["automatic_changes"] is False
    model = build_probabilistic_application_model(persisted, generated_at=INGESTED)
    for context in (model["observation_context"], model["learning_profile_history"]["observation_records"][0]):
        for key in ("observation_id", "session_id", "flow_key", "event_timestamp", "ingested_at"):
            expected = persisted[key]
            if context is model["observation_context"] and expected == "":
                expected = "-"
            assert context[key] == expected
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
        for label, key in (("Flow Key", "flow_key"), ("Session ID", "session_id")):
            assert details[label] == (persisted[key] or "not applicable")
    if observation["identity_scope"] == "listener":
        assert observation["observation_id"]
        assert observation["evidence_origin"] == "listener_socket_observation"
        assert observation["session_id"] == observation["flow_key"] == ""
        assert event["flows"] == []
        assert gui_app._packet_activity_rows(build_flow_report(event["flows"])["flows"]) == []
    else:
        assert event["flows"][0]["pcap_generated"] is False
        packet_flow = build_flow_report(event["flows"])["flows"][0]
        assert packet_flow["event_count"] == packet_flow["socket_observation_count"] == 1
        assert packet_flow["captured_packet_count"] == packet_flow["packet_count"] == packet_flow["captured_bytes"] == 0
        assert packet_flow["counter_provenance"] == "socket_observation"
        packet = gui_app._packet_activity_rows([packet_flow])[0]
        for key in ("observation_id", "flow_key", "session_id"):
            assert packet[key] == observation[key]
        packet_details = dict(gui_app._packet_detail_rows(packet))
        assert packet_details["Packets"] == "not measured" and packet_details["Bytes"] == "-"
        assert packet["mode"] == "read_only" and packet["execution"] == "not performed"
        assert packet["event_time_utc"] == "2026-07-05 02:19:22 UTC"
        assert packet["ingested_at_utc"] == "2026-07-05 02:19:52 UTC"
    from core_engine import log_exporter
    monkeypatch.setattr(log_exporter, "ensure_runtime_dirs", lambda: None)
    monkeypatch.setattr(log_exporter, "LOG_DIR", tmp_path)
    monkeypatch.setattr(log_exporter, "utc_now_iso", lambda: INGESTED)
    archive_path = log_exporter.export_logs(output_dir=tmp_path / "exports", include_state=False)
    with ZipFile(archive_path) as archive:
        assert archive.read(f"{tmp_path.name}/{path.name}") == path.read_bytes()
    assert model["automated_action"] is False


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


def test_worker_resampling_replay_and_reloaded_views_preserve_identity_lifecycle(tmp_path, monkeypatch):
    path = tmp_path / "master_events.log"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    monkeypatch.setattr(gui_app, "MASTER_EVENTS_LOG", path)
    monkeypatch.setattr(gui_app, "FLOW_EVENTS_LOG", tmp_path / "absent-flow-source.jsonl")
    monkeypatch.setattr(worker_node, "get_score", lambda row, use_ml=False: 0.4)
    def unexpected_action(*args, **kwargs):
        pytest.fail("Read-only telemetry must not invoke remediation")
    monkeypatch.setattr(dispatcher, "handle_remediation", unexpected_action)
    rows = [socket_row(remote=peer, ai_provider="heuristic") for peer in ("198.51.100.20:22", "198.51.100.21:22")]
    rows.append(socket_row(local="192.0.2.10:22", port=22, remote="-", status="LISTEN", ai_provider="heuristic"))
    for row in rows:
        row.pop("timestamp")
        row.pop("node_id")
    original = copy.deepcopy(rows)
    logger = logging.getLogger("test-lifecycle")
    snapshots = []
    for instant in (EVENT, INGESTED):
        monkeypatch.setattr(worker_node, "utc_now_iso", lambda: instant)
        monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: "2026-07-05T02:20:02Z")
        for node in ("worker-a", "worker-b"):
            payload = worker_node.build_payload(node, rows, logger, False)
            snapshots.append(payload)
            assert dispatcher.dispatch_alert(json.loads(json.dumps(payload)), logger=logger) is None
    assert rows == original
    for first, second in zip(snapshots[:2], snapshots[2:]):
        assert first["scan_snapshot"]["snapshot_id"] == second["scan_snapshot"]["snapshot_id"]
        for before, after in zip(first["ports"], second["ports"]):
            assert before["observation_id"] != after["observation_id"]
            assert before["session_id"] == after["session_id"]
            assert before["flow_key"] == after["flow_key"]
    # Recreate the same worker sample after serialization, without retaining any bridge state.
    restarted_payload = worker_node.build_payload("worker-b", rows, logger, False)
    assert restarted_payload == snapshots[-1]
    dispatcher.dispatch_alert(restarted_payload, logger=logger)
    events = [json.loads(line) for line in path.read_text().splitlines()]
    samples = [row for event in events[:4] for row in event["observations"]]
    assert len(samples) == len({row["observation_id"] for row in samples}) == 12
    db_path = tmp_path / "samples.sqlite"
    with SQLiteStore(db_path) as store:
        repository = LocalStorageRepository(store)
        for sample in samples:
            repository.insert_event({**sample, "event_id": sample["observation_id"], "event_type": "network_observation", "severity": "low", "source": "worker", "message": "Socket metadata"})
    with SQLiteStore(db_path) as store:
        status, response = create_local_api_app(repository=LocalStorageRepository(store)).get("/events")
        assert status == 200
        assert {row["observation_id"] for row in response["items"]} == {row["observation_id"] for row in samples}
    expected_current = {row["observation_id"] for event in events[2:4] for row in event["observations"]}
    # Fresh dashboard instances reload persisted logs; no server or live collector is started.
    first_dashboard, restarted_dashboard = gui_app.PortMapDashboard(), gui_app.PortMapDashboard()
    for dashboard in (first_dashboard, restarted_dashboard, restarted_dashboard):
        scans = dashboard._load_scan_results()
        assert {row["observation_id"] for row in scans} == expected_current
        for view in (gui_app._active_risk_finding_rows([], scans), gui_app._ai_provider_model_rows(gui_app._ai_events_from_sources(scan_results=scans))):
            assert {row["observation_id"] for row in view} == expected_current
        flows = dashboard._load_flow_visualization()["flows"]
        assert len(flows) == 4
        assert len({flow["source_flow_key"] for flow in flows}) == 4
        for flow in flows:
            assert flow["event_count"] == flow["socket_observation_count"] == 2
            assert flow["captured_packet_count"] == flow["captured_bytes"] == 0
            assert len(flow["observation_ids"]) == 2 and flow["observation_id"] == ""
            assert flow["duration_seconds"] == 30
            assert set(flow["observation_ids"]) <= {row["observation_id"] for row in samples}


@pytest.mark.parametrize("order", [(1, 2, 0, 0), (0, 1, 2, 0)])
def test_out_of_order_skewed_worker_delivery_and_replay_preserve_source_evidence(tmp_path, monkeypatch, order):
    path = tmp_path / "master_events.log"
    monkeypatch.setattr(dispatcher, "MASTER_LOG", path)
    monkeypatch.setattr(worker_node, "get_score", lambda *args, **kwargs: 0.4)
    sources = [("worker-a", "2026-07-04T22:19:22-04:00"),
               ("worker-a", INGESTED), ("worker-b", "2026-07-05T04:24:22+02:00")]
    payloads = []
    for node, instant in sources:
        monkeypatch.setattr(worker_node, "utc_now_iso", lambda: instant)
        payloads.append(worker_node.build_payload(node, [socket_row(timestamp=instant, ai_provider="heuristic")], logging.getLogger("test.skew"), False))
    arrivals = [f"2026-07-05T02:20:0{second}Z" for second in range(2, 6)]
    for index, received in zip(order, arrivals):
        monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: received)
        dispatcher.dispatch_alert(copy.deepcopy(payloads[index]))
    events = [json.loads(line) for line in path.read_text().splitlines()]
    db_path = tmp_path / "history.sqlite"
    stored = {}
    with SQLiteStore(db_path) as store:
        repository = LocalStorageRepository(store)
        for event, index, received in zip(events, order, arrivals):
            sample = event["observations"][0]
            for key in ("observation_id", "session_id", "flow_key", "node_id", "event_timestamp"):
                assert sample[key] == payloads[index]["ports"][0][key]
            assert sample["ingested_at"] == received
            record = {**sample, "event_id": sample["observation_id"], "event_type": "network_observation", "severity": "low", "source": "worker", "message": "Socket metadata"}
            if sample["observation_id"] in stored:
                with pytest.raises(StorageError, match="UNIQUE constraint"):
                    repository.insert_event(record)
            else:
                repository.insert_event(record)
                stored[sample["observation_id"]] = record
    with SQLiteStore(db_path) as store:
        restored = create_local_api_app(repository=LocalStorageRepository(store)).get("/events")[1]["items"]
        assert restored == list(stored.values())  # Rejected replay never overwrites first receipt.
    flows = build_flow_report([flow for event in events for flow in event["flows"]])["flows"]
    assert len(flows) == 2
    assert sum(flow["event_count"] for flow in flows) == 3  # Four deliveries, three samples.
    worker_a = next(flow for flow in flows if flow["node_id"] == "worker-a")
    assert worker_a["duration_seconds"] == 30
    assert len(worker_a["observation_ids"]) == 2
    scans = gui_app._scan_rows_from_telemetry(events)
    # Receipt order controls the current snapshot, not an uncorrected worker clock.
    current_a = next(row for row in scans if row["node_id"] == "worker-a")
    assert current_a["observation_id"] == payloads[0]["ports"][0]["observation_id"]
    for view in (gui_app._active_risk_finding_rows([], scans), gui_app._ai_provider_model_rows(gui_app._ai_events_from_sources(scan_results=scans))):
        assert {row["observation_id"] for row in view} == {row["observation_id"] for row in scans}
    assert all(flow["captured_packet_count"] == flow["captured_bytes"] == 0 for flow in flows)


@pytest.mark.parametrize("upstream_lifetime", [False, True])
@pytest.mark.parametrize("later,windows", [(INGESTED, 1), ("2026-07-06T02:19:22Z", 2)])
def test_reused_tuple_only_separates_connection_lifetimes_with_source_references(upstream_lifetime, later, windows):
    events = []
    for index, instant in enumerate((EVENT, later)):
        references = {"session_id": f"upstream-session-{index}", "flow_key": f"upstream-flow-{index}"} if upstream_lifetime else {}
        report = build_milestone_v_runtime_bridge([socket_row(timestamp=instant, **references)], generated_at=instant)
        events.extend(report["flow_events"])
    assert events[0]["observation_id"] != events[1]["observation_id"]
    flows = build_flow_report(events)["flows"]
    if upstream_lifetime:
        assert len(flows) == 2
        assert {flow["session_id"] for flow in flows} == {"upstream-session-0", "upstream-session-1"}
        assert {flow["source_flow_key"] for flow in flows} == {"upstream-flow-0", "upstream-flow-1"}
    else:
        assert len(flows) == windows  # An aggregation window is not a proven TCP lifetime.
        assert events[0]["session_id"] == events[1]["session_id"]
        assert {flow["session_id"] for flow in flows} == {events[0]["session_id"]}
        assert sorted(value for flow in flows for value in flow["observation_ids"]) == sorted(event["observation_id"] for event in events)


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


@pytest.mark.parametrize("changes", [
    {},
    {"status": "LISTEN", "local": "192.0.2.10:22", "port": 22, "remote": "-"},
    {"protocol": "UDP", "status": "NONE"},
    {"local": "[2001:db8::10]:51515", "remote": "[2001:db8::20]:22"},
])
def test_risk_decision_retains_the_selected_observation_time_and_identity(tmp_path, monkeypatch, changes):
    monkeypatch.setattr(dispatcher, "MASTER_LOG", tmp_path / "events.jsonl")
    risk_path = tmp_path / "risk.jsonl"
    monkeypatch.setattr(dispatcher, "REMEDIATION_LOG", risk_path)
    monkeypatch.setattr(dispatcher, "utc_timestamp", lambda: INGESTED)
    monkeypatch.setattr(dispatcher, "record_audit_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(dispatcher, "handle_remediation", lambda *args: SimpleNamespace(action="prompt_operator", reason="metadata review", score=0.8, mode="prompt"))
    dispatcher.dispatch_alert({"node_id": "worker-a", "timestamp": INGESTED, "ports": [socket_row(score=0.8, **changes)]}, settings={})
    event = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])
    risk = json.loads(risk_path.read_text().splitlines()[0])
    for key in ("observation_id", "flow_key", "session_id", "event_timestamp", "ingested_at", "identity_scope", "evidence_origin", "local_address", "remote_address"):
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
