from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from core_engine.capture.models import normalize_timestamp as normalize_capture_timestamp
from core_engine.dispatcher import dispatch_alert
from core_engine.modules.flow_tracker import build_flow_report
from core_engine.runtime.milestone_v_bridge import build_milestone_v_runtime_bridge
from core_engine.time_utils import (
    AmbiguousTimestampError,
    epoch_seconds,
    format_utc_label,
    normalize_timestamp,
    parse_utc_instant,
    utc_isoformat,
)
from gui import app as gui_app
from gui import visualization


def test_aware_eastern_time_converts_to_canonical_utc_rollover():
    eastern = datetime(2026, 7, 4, 22, 34, 11, tzinfo=ZoneInfo("America/New_York"))

    assert normalize_timestamp(eastern) == "2026-07-05T02:34:11Z"
    assert format_utc_label(eastern) == "2026-07-05 02:34:11 UTC"


def test_aware_central_european_summer_time_converts_to_utc():
    berlin = datetime(2026, 7, 5, 6, 34, 11, tzinfo=ZoneInfo("Europe/Berlin"))

    assert normalize_timestamp(berlin) == "2026-07-05T04:34:11Z"


def test_already_utc_timestamp_preserves_the_same_instant():
    value = "2026-07-05T04:34:11Z"

    assert normalize_timestamp(value) == value
    assert epoch_seconds(value) == epoch_seconds("2026-07-05T04:34:11+00:00")


def test_naive_datetimes_are_rejected_and_legacy_strings_are_ambiguous():
    with pytest.raises(AmbiguousTimestampError):
        utc_isoformat(datetime(2026, 7, 5, 4, 34, 11))

    legacy = "2026-07-05 00:34:11"
    assert normalize_timestamp(legacy) == legacy
    assert parse_utc_instant(legacy) is None
    assert format_utc_label(legacy) == "2026-07-05 00:34:11 (timezone ambiguous)"


def test_capture_timestamp_normalization_does_not_label_naive_datetime_as_utc():
    aware = datetime(2026, 7, 4, 22, 34, 11, tzinfo=ZoneInfo("America/New_York"))
    assert normalize_capture_timestamp(aware) == "2026-07-05T02:34:11Z"
    assert normalize_capture_timestamp("2026-07-05 00:34:11") == "2026-07-05 00:34:11"


def test_worker_runtime_flow_packet_and_tui_round_trip_preserves_utc_instant():
    generated_at = "2026-07-05T04:34:11Z"
    report = build_milestone_v_runtime_bridge(
        [
            {
                "program": "sshd",
                "pid": 0,
                "port": 51515,
                "service_name": "ssh",
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "local": "192.0.2.10:51515",
                "remote": "198.51.100.20:22",
                "source_mode": "live",
                "data_source": "local_socket_inventory",
            }
        ],
        node_id="worker-fixture",
        generated_at=generated_at,
    )

    assert report["generated_at"] == generated_at
    assert report["flow_events"][0]["timestamp"] == generated_at

    flow_visualization = visualization.build_flow_visualization(report["flow_events"])
    packet_row = gui_app._packet_activity_rows(flow_visualization["flows"])[0]
    packet_details = dict(gui_app._packet_detail_rows(packet_row))
    risk_row = gui_app._active_risk_finding_rows([], [{"timestamp": generated_at, "node_id": "worker-fixture", "port": 22, "protocol": "tcp", "state": "ESTABLISHED"}])[0]
    ai_row = gui_app._ai_provider_model_rows(
        gui_app._ai_events_from_sources(
            master_events=[
                {
                    "timestamp": generated_at,
                    "event_type": "ai_decision",
                    "ai_provider": "heuristic",
                    "ai_model": "probabilistic",
                    "node_id": "worker-fixture",
                    "port": 22,
                    "protocol": "tcp",
                    "state": "ESTABLISHED",
                }
            ]
        )
    )[0]

    assert packet_details["Event Time UTC"] == "2026-07-05 04:34:11 UTC"
    assert dict(gui_app._finding_detail_rows(risk_row))["Event Time UTC"] == "2026-07-05 04:34:11 UTC"
    assert dict(gui_app._ai_detail_rows(ai_row))["Event Time UTC"] == "2026-07-05 04:34:11 UTC"
    assert packet_row["last_seen"] == "2026-07-05 04:34:11 UTC"


def test_prevention_of_double_utc_conversion_for_epoch_packet_times():
    instant = "2026-07-05T04:34:11Z"
    epoch = epoch_seconds(instant)

    flow_report = build_flow_report(
        [
            {
                "timestamp": epoch,
                "src_ip": "192.0.2.10",
                "src_port": 51515,
                "dst_ip": "198.51.100.20",
                "dst_port": 22,
                "protocol": "TCP",
            }
        ]
    )
    packet_row = gui_app._packet_activity_rows(flow_report["flows"])[0]

    assert packet_row["last_seen"] == "2026-07-05 04:34:11 UTC"
    assert packet_row["event_time_utc"] == "2026-07-05 04:34:11 UTC"


def test_identical_instants_from_workers_in_different_timezones_correlate():
    eastern = normalize_timestamp(datetime(2026, 7, 4, 22, 34, 11, tzinfo=ZoneInfo("America/New_York")))
    berlin = normalize_timestamp(datetime(2026, 7, 5, 4, 34, 11, tzinfo=ZoneInfo("Europe/Berlin")))

    assert eastern == berlin == "2026-07-05T02:34:11Z"
    assert epoch_seconds(eastern) == epoch_seconds(berlin)


def test_dispatcher_storage_timestamp_is_canonical_utc(monkeypatch, tmp_path):
    master_log = tmp_path / "master_events.log"
    monkeypatch.setattr("core_engine.dispatcher.MASTER_LOG", master_log)

    dispatch_alert(
        {
            "node_id": "worker-fixture",
            "score": 0.2,
            "ports": [
                {
                    "program": "sshd",
                    "port": 22,
                    "service_name": "ssh",
                    "protocol": "TCP",
                    "status": "LISTEN",
                    "local": "192.0.2.10:22",
                    "remote": "",
                    "source_mode": "live",
                }
            ],
        },
        settings=None,
    )

    event = __import__("json").loads(master_log.read_text().splitlines()[0])
    assert event["timestamp"].endswith("Z")
    assert parse_utc_instant(event["timestamp"]) is not None
    assert event["milestone_v"]["generated_at"] == event["timestamp"]
