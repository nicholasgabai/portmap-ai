import json

from core_engine.timeline import (
    PacketTimelineEngine,
    TimelineEvent,
    build_packet_timeline,
    build_timeline_sessions,
    export_timeline,
    filter_by_conversation,
    filter_by_host,
    filter_by_importance,
    filter_by_protocol,
    filter_by_session,
    filter_by_time_range,
    flow_lifecycle_events,
    group_by_conversation,
    group_by_flow,
    group_by_host_pair,
    group_by_interface,
    group_by_port_pair,
    group_by_protocol,
    group_by_session,
    merge_timelines,
    session_lifecycle_events,
    timeline_export_summary,
    timeline_gap_event,
    timeline_statistics,
)


def _packet(**overrides):
    data = {
        "packet_id": "packet-a",
        "session_id": "session-a",
        "observed_at": "2026-06-14T12:00:00+00:00",
        "interface": "mock0",
        "direction": "outbound",
        "length": 64,
        "captured_length": 64,
        "link_type": "ethernet",
        "eth_src": "aa:bb:cc:dd:ee:ff",
        "eth_dst": "11:22:33:44:55:66",
        "ether_type": "0x0800",
        "ip_version": 4,
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.10",
        "ttl": 64,
        "protocol": "TCP",
        "src_port": 51515,
        "dst_port": 443,
        "tcp_flags": ["SYN"],
        "payload_length": 0,
        "tags": ["fixture"],
        "metadata": {"safe": "yes"},
    }
    data.update(overrides)
    return data


def _packets():
    return [
        _packet(packet_id="packet-b", observed_at="2026-06-14T12:00:03+00:00", dst_port=443, length=70),
        _packet(packet_id="packet-a", observed_at="2026-06-14T12:00:00+00:00", dst_port=443, length=60),
        _packet(
            packet_id="packet-c",
            session_id="session-b",
            observed_at="2026-06-14T12:00:01+00:00",
            protocol="UDP",
            src_port=53000,
            dst_port=53,
            length=80,
        ),
    ]


def test_timeline_creation_and_event_ordering():
    events = build_packet_timeline(_packets())

    assert events
    assert events == sorted(events, key=lambda row: (row["timestamp"], row["event_type"], row["event_id"], row["packet_id"]))
    assert {event["event_type"] for event in events} >= {
        "packet_observed",
        "protocol_detected",
        "conversation_started",
        "conversation_updated",
        "conversation_completed",
    }
    assert events[0]["timestamp"] == "2026-06-14T12:00:00+00:00"


def test_timeline_event_stable_ids_and_json_safe_output():
    first = TimelineEvent.from_dict({"timestamp": "2026-06-14T12:00:00+00:00", "event_type": "packet_observed"})
    second = TimelineEvent.from_dict({"event_type": "packet_observed", "timestamp": "2026-06-14T12:00:00+00:00"})

    assert first.event_id == second.event_id
    rendered = first.to_dict()
    assert rendered["event_type"] == "packet_observed"
    json.dumps(rendered, sort_keys=True)


def test_conversation_reconstruction_lifecycle():
    events = build_packet_timeline(_packets())
    started = [event for event in events if event["event_type"] == "conversation_started"]
    completed = [event for event in events if event["event_type"] == "conversation_completed"]

    assert len(started) == 2
    assert len(completed) == 2
    https = next(event for event in completed if event["protocol"] == "https")
    assert https["metadata"]["packet_count"] == 2
    assert https["metadata"]["byte_count"] == 130


def test_flow_reconstruction_lifecycle_events():
    timeline = build_packet_timeline(_packets())
    # Build from protocol conversation summaries exposed by the engine output.
    completed = [event for event in timeline if event["event_type"] == "conversation_completed"]
    flow_events = flow_lifecycle_events(
        [
            {
                "conversation_id": event["conversation_id"],
                "flow_key": event["flow_key"],
                "protocol": event["protocol"],
                "first_observed": event["timestamp"],
                "last_observed": event["timestamp"],
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "src_port": event["src_port"],
                "dst_port": event["dst_port"],
                "direction": event["direction"],
                "confidence": event["confidence"],
            }
            for event in completed
        ]
    )

    assert {event["event_type"] for event in flow_events} == {"flow_created", "flow_updated", "flow_completed"}


def test_session_reconstruction_and_lifecycle_events():
    events = build_packet_timeline(_packets())
    sessions = build_timeline_sessions(events)
    lifecycle = session_lifecycle_events(events)

    assert {session["session_id"] for session in sessions} == {"session-a", "session-b"}
    session_a = next(session for session in sessions if session["session_id"] == "session-a")
    assert session_a["packet_count"] == 2
    assert session_a["byte_count"] == 130
    assert session_a["duration"] == 3
    assert {event["event_type"] for event in lifecycle} == {"session_started", "session_updated", "session_completed"}


def test_protocol_events_include_evidence_and_confidence():
    events = build_packet_timeline([_packet(packet_id="dns", protocol="UDP", dst_port=53)])
    protocol_event = next(event for event in events if event["event_type"] == "protocol_detected")

    assert protocol_event["protocol"] == "dns"
    assert protocol_event["confidence"] > 0
    assert "port:53" in protocol_event["evidence"]


def test_merge_behavior_deduplicates_and_marks_merge():
    timeline = build_packet_timeline([_packet()])
    merged = merge_timelines(timeline, timeline)

    assert len(merged) == len(timeline) + 1
    assert any(event["event_type"] == "timeline_merge" for event in merged)
    assert len({event["event_id"] for event in merged}) == len(merged)


def test_filter_helpers_are_deterministic():
    events = build_packet_timeline(_packets())
    conversation_id = next(event["conversation_id"] for event in events if event["conversation_id"] != "-")

    assert filter_by_time_range(events, start="2026-06-14T12:00:01+00:00")
    assert all(event["conversation_id"] == conversation_id for event in filter_by_conversation(events, conversation_id))
    assert all(event["protocol"] == "dns" for event in filter_by_protocol(events, "dns"))
    assert all("203.0.113.10" in {event["src_ip"], event["dst_ip"]} for event in filter_by_host(events, "203.0.113.10"))
    assert all(event["session_id"] == "session-a" for event in filter_by_session(events, "session-a"))
    assert all(event["importance"] == "high" for event in filter_by_importance(events, "high"))


def test_correlation_group_helpers():
    events = build_packet_timeline(_packets())

    assert group_by_conversation(events)
    assert group_by_flow(events)
    assert set(group_by_protocol(events)) >= {"https", "dns"}
    assert set(group_by_session(events)) >= {"session-a", "session-b"}
    assert set(group_by_interface(events)) >= {"mock0"}
    assert group_by_host_pair(events)
    assert group_by_port_pair(events)


def test_timeline_statistics_summary():
    events = build_packet_timeline(_packets())
    stats = timeline_statistics(events)

    assert stats["event_count"] == len(events)
    assert stats["conversation_count"] == 2
    assert stats["flow_count"] == 2
    assert stats["session_count"] == 2
    assert stats["duration"] == 3
    assert stats["events_per_protocol"]["https"] > 0
    assert stats["events_per_interface"]["mock0"] > 0
    assert stats["first_event"] != "-"
    assert stats["last_event"] != "-"
    assert stats["largest_conversation"] != "-"
    assert stats["largest_session"] != "-"


def test_empty_input_is_safe_and_json_serializable():
    engine = PacketTimelineEngine()
    timeline = engine.build_timeline([])
    stats = timeline_statistics(timeline)
    summary = timeline_export_summary(timeline)

    assert timeline == []
    assert stats["event_count"] == 0
    assert stats["first_event"] == "-"
    assert summary == {"event_count": 0, "first_event": "-", "last_event": "-", "events": []}
    json.dumps(stats, sort_keys=True)


def test_duplicate_suppression_and_timestamp_sorting():
    event_a = TimelineEvent.from_dict({"timestamp": "2026-06-14T12:00:02+00:00", "event_type": "unknown"})
    event_b = TimelineEvent.from_dict({"timestamp": "2026-06-14T12:00:01+00:00", "event_type": "unknown"})

    exported = export_timeline([event_a, event_b, event_a])

    assert [event["timestamp"] for event in exported] == [
        "2026-06-14T12:00:01+00:00",
        "2026-06-14T12:00:02+00:00",
        "2026-06-14T12:00:02+00:00",
    ]
    assert len(exported) == 3
    assert len(merge_timelines(exported, exported)) == 3


def test_timeline_gap_event():
    previous = {"event_id": "event-a", "timestamp": "2026-06-14T12:00:00+00:00", "flow_key": "flow"}
    current = {"event_id": "event-b", "timestamp": "2026-06-14T12:05:00+00:00", "flow_key": "flow"}

    gap = timeline_gap_event(previous, current, gap_seconds=300)

    assert gap["event_type"] == "timeline_gap"
    assert gap["metadata"]["gap_seconds"] == 300
    assert gap["evidence"] == ["event-a", "event-b"]


def test_deterministic_output_for_identical_input():
    first = build_packet_timeline(_packets())
    second = build_packet_timeline(list(reversed(_packets())))

    assert first == second


def test_no_mutation_and_no_payload_storage():
    packet = _packet(payload="secret", raw_bytes=b"hidden", metadata={"payload_body": "secret", "safe": "yes"})
    original = dict(packet)

    events = build_packet_timeline([packet])

    assert packet == original
    rendered = json.dumps(events, sort_keys=True)
    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert all("payload" not in event for event in events)
