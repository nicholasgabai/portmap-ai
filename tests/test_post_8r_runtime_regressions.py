import copy
import json
from contextlib import contextmanager
from urllib import error

import pytest

from core_engine.api import create_local_api_app
from core_engine.attribution import build_probabilistic_application_model
from core_engine.modules.flow_tracker import build_flow_report
from core_engine.observation_identity import observation_identity
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge
from core_engine.storage import LocalStorageRepository, SQLiteStore
from core_engine.time_utils import format_utc_label, parse_utc_instant
from gui import app as gui
from gui import visualization


EVENT = "2026-07-05T02:19:22Z"
RECEIVED = "2026-07-05T02:19:52Z"


def socket_row(**changes):
    row = {
        "node_id": "worker-example", "local": "192.0.2.10:22", "remote": "198.51.100.20:51515",
        "port": 22, "protocol": "tcp", "status": "ESTABLISHED", "source_mode": "live",
        "program": "sshd", "service_name": "ssh", "event_timestamp": EVENT, "ingested_at": RECEIVED,
    }
    return {**row, **changes}


def flow_event(**changes):
    return build_milestone_v_runtime_bridge([socket_row(**changes)], generated_at=RECEIVED)["flow_events"][0]


@contextmanager
def response(payload):
    class Response:
        def read(self):
            return json.dumps(payload).encode()
    yield Response()


@pytest.mark.parametrize("failure,status", [
    (TimeoutError(), "timeout"),
    (error.URLError(TimeoutError()), "timeout"),
    (error.URLError(ConnectionRefusedError()), "connection_error"),
    (error.HTTPError("http://example.invalid", 401, "Unauthorized", {}, None), "http_401"),
])
def test_health_failure_does_not_claim_process_crash(monkeypatch, failure, status):
    dashboard = gui.PortMapDashboard()
    dashboard.orchestrator_url = "http://example.invalid"
    dashboard.orchestrator_token = "private-test-value"
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(gui.request, "urlopen", fail)
    health = dashboard._load_orchestrator_health()
    assert health["status"] == status
    assert health["last_success_at"] is None
    assert health["checked_at"].endswith("Z")
    assert "private-test-value" not in json.dumps(health)
    assert "crash" not in json.dumps(health)


@pytest.mark.parametrize("payload", [None, [], {}, {"status": 1}])
def test_invalid_health_response_is_not_reported_as_ok_or_connection_failure(monkeypatch, payload):
    dashboard = gui.PortMapDashboard()
    monkeypatch.setattr(gui.request, "urlopen", lambda *args, **kwargs: response(payload))
    assert dashboard._load_orchestrator_health()["status"] == "invalid_response"


def test_health_success_timeout_and_recovery_do_not_reuse_stale_status(monkeypatch):
    dashboard = gui.PortMapDashboard()
    checked = iter([EVENT, RECEIVED, "2026-07-05T02:20:02Z"])
    monkeypatch.setattr(gui, "utc_now_iso", lambda: next(checked))
    def get(req, timeout):
        assert timeout == 2.0
        return response({"status": "ok"} if req.full_url.endswith("/healthz") else {"heartbeats": 4})
    monkeypatch.setattr(gui.request, "urlopen", get)
    first = dashboard._load_orchestrator_health()
    def fail(*args, **kwargs):
        raise TimeoutError()
    monkeypatch.setattr(gui.request, "urlopen", fail)
    failed = dashboard._load_orchestrator_health()
    assert first["status"] == "ok" and failed["status"] == "timeout"
    assert failed["last_success_at"] == EVENT
    assert failed["checked_at"] == RECEIVED
    assert failed["metrics"] == {}
    monkeypatch.setattr(gui.request, "urlopen", get)
    recovered = dashboard._load_orchestrator_health()
    assert recovered["status"] == recovered["metrics_status"] == "ok"
    assert recovered["last_success_at"] == recovered["checked_at"] == "2026-07-05T02:20:02Z"


def test_metrics_failure_does_not_change_successful_health_result(monkeypatch):
    dashboard = gui.PortMapDashboard()
    def get(req, timeout):
        if req.full_url.endswith("/healthz"):
            return response({"status": "ok"})
        raise TimeoutError()
    monkeypatch.setattr(gui.request, "urlopen", get)
    health = dashboard._load_orchestrator_health()
    assert health["status"] == "ok"
    assert health["metrics_status"] == "unavailable"
    assert health["last_success_at"] == health["checked_at"]


def test_listener_cannot_inherit_established_conversation_aliases():
    established = socket_row()
    conversation = observation_identity(established)
    listener = socket_row(status="LISTEN", **{key: conversation[key] for key in ("session_id", "flow_key")}, session_ref=conversation["session_id"], session_reference=conversation["session_id"], flow_id=conversation["flow_key"])
    original = copy.deepcopy(listener)
    report = build_milestone_v_runtime_bridge([listener, established], generated_at=RECEIVED)
    assert listener == original
    normalized_listener = next(row for row in report["observations"] if row["identity_scope"] == "listener")
    normalized_connection = next(row for row in report["observations"] if row["identity_scope"] == "flow")
    assert normalized_listener["observation_id"] != normalized_connection["observation_id"]
    for key in ("session_id", "flow_key", "session_ref", "session_reference", "flow_id"):
        assert normalized_listener.get(key, "") == ""
    assert report["runtime_counters"]["sessions_reconstructed"] == report["runtime_counters"]["flows_reconstructed"] == 1
    assert len(report["flow_events"]) == 1
    assert report["flow_events"][0]["observation_id"] == normalized_connection["observation_id"]
    for correlation in report["api_status"]["metadata_correlations"]["metadata_correlations"]:
        if correlation["observation_id"] == normalized_listener["observation_id"]:
            assert correlation["session_id"] == correlation["flow_key"] == ""
    for details in (gui._finding_detail_rows(gui._active_risk_finding_rows([], [normalized_listener])[0]), gui._ai_detail_rows(gui._ai_provider_model_rows([{**normalized_listener, "ai_provider": "heuristic"}])[0])):
        assert dict(details)["Session ID"] == dict(details)["Flow Key"] == "not applicable"


def test_incomplete_socket_does_not_generate_a_session_reference():
    identity = observation_identity({"node_id": "worker-example", "port": 22, "status": "ESTABLISHED", "event_timestamp": EVENT})
    assert identity["identity_scope"] == "socket"
    assert identity["session_id"] == identity["flow_key"] == ""
    assert identity["observation_id"]


def test_listener_process_correlation_ids_remain_scoped_without_session_ids():
    report = build_milestone_v_runtime_bridge([
        socket_row(status="LISTEN"),
        socket_row(status="LISTEN", node_id="worker-other"),
        socket_row(status="LISTEN", local="192.0.2.11:22"),
    ], generated_at=RECEIVED)
    rows = report["api_status"]["process_correlations"]["process_correlations"]
    assert len(rows) == len({row["process_correlation_id"] for row in rows}) == 3
    assert all(row["session_id"] == row["flow_key"] == "" for row in rows)


def test_legacy_listener_loads_verbatim_but_is_not_reinterpreted_as_a_session(tmp_path):
    legacy = socket_row(status="LISTEN", identity_scope="listener", observation_id="legacy-listener", flow_key="legacy-flow", session_id="legacy-session")
    original = copy.deepcopy(legacy)
    with SQLiteStore(tmp_path / "legacy.sqlite") as store:
        repository = LocalStorageRepository(store)
        repository.insert_finding(legacy)
        loaded = repository.list_findings()[0]
    assert all(loaded[key] == value for key, value in original.items())
    model = build_probabilistic_application_model(loaded, generated_at=RECEIVED)
    assert model["observation_context"]["flow_key"] == model["observation_context"]["session_id"] == "-"
    assert model["learning_profile_history"]["observation_records"][0]["session_id"] == ""
    assert model["behavior_graph"]["summary"]["related_session"] == "-"
    assert legacy == original


def test_socket_event_counts_are_not_packets_or_measured_bytes():
    first, second = flow_event(), flow_event(event_timestamp=RECEIVED)
    report = build_flow_report([first, first, second])
    flow = report["flows"][0]
    assert flow["event_count"] == flow["socket_observation_count"] == 2
    assert flow["packet_count"] == flow["captured_packet_count"] == flow["captured_bytes"] == 0
    assert flow["counter_provenance"] == "socket_observation"
    assert flow["observation_id"] == ""
    assert flow["observation_ids"] == sorted([first["observation_id"], second["observation_id"]])
    row = gui._packet_activity_rows([flow])[0]
    details = dict(gui._packet_detail_rows(row))
    assert row["packets"] == details["Event Count"] == "2"
    assert details["Packets"] == "not measured" and details["Bytes"] == "-"
    assert details["Session Count"] == "1"
    assert details["Counter Provenance"] == "socket_observation"
    assert all(value in details["Observation IDs"] for value in flow["observation_ids"])
    assert gui._packet_summary_rows([row])[0]["bytes"] == "-"
    assert gui._packet_timeline_rows([row])[0]["bytes"] == "-"


@pytest.mark.parametrize("kind", ["os_counter", "estimated", "synthetic"])
def test_other_counter_sources_do_not_become_captured_packets(kind):
    event = {**flow_event(), "counter_provenance": kind, "telemetry_source": kind, "evidence_origin": kind, "packet_count": 999}
    flow = build_flow_report([event])["flows"][0]
    assert flow["counter_provenance"] == kind
    assert flow["captured_packet_count"] == flow["packet_count"] == 0
    assert flow["event_count"] == 1
    assert gui._packet_activity_rows([flow])[0]["bytes"] == "-"


def test_authorized_capture_metadata_remains_distinct_from_socket_counts():
    socket = flow_event()
    capture = {**socket, "telemetry_source": "packet_metadata", "evidence_origin": "packet_metadata", "counter_provenance": "captured_packet", "captured_len": 88, "payload_bytes": 10}
    report = build_flow_report([socket, capture])
    assert len(report["flows"]) == 2
    measured = next(row for row in report["flows"] if row["counter_provenance"] == "captured_packet")
    assert measured["packet_count"] == measured["captured_packet_count"] == 1
    assert measured["captured_bytes"] == 88
    details = dict(gui._packet_detail_rows(gui._packet_activity_rows([measured])[0]))
    assert details["Packets"] == "1" and details["Bytes"] == "88"
    edge = report["topology"]["edges"][0]
    assert edge["event_count"] == 2 and edge["captured_packet_count"] == edge["socket_observation_count"] == 1
    assert edge["counter_sources"] == {"captured_packet": 1, "socket_observation": 1}
    assert visualization.topology_edge_rows(report["topology"])[0]["bytes_measured"] is False
    assert visualization.flow_rows([next(row for row in report["flows"] if row["counter_provenance"] == "socket_observation")])[0]["bytes_measured"] is False


def test_fixture_socket_metadata_never_becomes_measured_capture():
    event = {**flow_event(), "source_mode": "fixture", "captured_len": 100, "payload_bytes": 40}
    flow = build_flow_report([event])["flows"][0]
    assert flow["counter_provenance"] == "synthetic"
    assert flow["source_mode"] == "fixture"
    assert flow["captured_packet_count"] == flow["packet_count"] == 0
    details = dict(gui._packet_detail_rows(gui._packet_activity_rows([flow])[0]))
    assert details["Source Mode"] == "fixture"
    assert details["Packets"] == "not measured"


def test_original_length_alone_is_not_capture_evidence():
    event = {**flow_event(), "telemetry_source": "legacy_metadata", "evidence_origin": "legacy_metadata", "counter_provenance": "captured_packet", "metadata": {"original_len": 100}}
    event.pop("captured_len")
    flow = build_flow_report([event])["flows"][0]
    assert flow["counter_provenance"] == "reported_packet_metadata"
    assert flow["captured_packet_count"] == flow["captured_bytes"] == 0


def test_legacy_reused_id_at_a_new_event_time_remains_a_distinct_sample():
    first, later = flow_event(), flow_event(event_timestamp=RECEIVED)
    first["observation_id"] = later["observation_id"] = "legacy-reused-id"
    flow = build_flow_report([first, later, first])["flows"][0]
    assert flow["event_count"] == 2
    assert flow["duration_seconds"] == 30


def test_sample_identity_and_counter_provenance_survive_storage_api_and_views(tmp_path):
    event = flow_event()
    record = {**event, "event_id": event["observation_id"], "severity": "low", "source": "worker", "message": "Socket metadata"}
    path = tmp_path / "events.sqlite"
    with SQLiteStore(path) as store:
        LocalStorageRepository(store).insert_event(record)
    with SQLiteStore(path) as store:
        status, response = create_local_api_app(repository=LocalStorageRepository(store)).get("/events")
        restored = response["items"][0]
    assert status == 200
    for key in ("observation_id", "flow_key", "session_id", "node_id", "event_timestamp", "ingested_at", "counter_provenance"):
        assert restored[key] == event[key]
    packet = gui._packet_activity_rows(build_flow_report([restored])["flows"])[0]
    risk = gui._active_risk_finding_rows([], [restored])[0]
    ai = gui._ai_provider_model_rows([{**restored, "ai_provider": "heuristic"}])[0]
    for row in (packet, risk, ai):
        for key in ("observation_id", "flow_key", "session_id"):
            assert row[key] == event[key]
        assert row["event_time_utc"] == "2026-07-05 02:19:22 UTC"
        assert row["ingested_at_utc"] == "2026-07-05 02:19:52 UTC"
    assert packet["node_id"] == risk["node"] == ai["node"] == event["node_id"]


@pytest.mark.parametrize("value", ["2026-07-04T22:19:22-04:00", EVENT, "2026-07-05 02:19:22 UTC"])
def test_explicit_utc_labels_are_idempotent_and_preserve_the_instant(value):
    once = format_utc_label(value)
    assert format_utc_label(once) == once == "2026-07-05 02:19:22 UTC"
    assert parse_utc_instant(value) == parse_utc_instant(EVENT)
    assert parse_utc_instant("2026-07-04 22:19:22") is None
