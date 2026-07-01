import json
import subprocess
from pathlib import Path

import pytest

from core_engine.capture import (
    CaptureManager,
    CaptureSession,
    MockCaptureAdapter,
    PacketMetadata,
    PcapFileMetadataAdapter,
    build_capture_filter,
    build_flow_key,
    summarize_packets,
    validate_capture_filter,
)


def _packet(**overrides):
    data = {
        "observed_at": "2026-06-14T12:00:00+00:00",
        "interface": "mock0",
        "direction": "outbound",
        "length": 64,
        "captured_length": 64,
        "eth_src": "aa:bb:cc:dd:ee:ff",
        "eth_dst": "11:22:33:44:55:66",
        "ether_type": "0x0800",
        "ip_version": 4,
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.10",
        "ttl": 64,
        "protocol": "tcp",
        "src_port": 51515,
        "dst_port": 443,
        "tcp_flags": ["syn"],
        "payload_length": 0,
        "tags": ["fixture"],
        "metadata": {"source": "unit"},
    }
    data.update(overrides)
    return data


def test_packet_metadata_normalization_and_json_output():
    source = _packet(payload_body="secret", raw_bytes=b"abc", metadata={"payload": "hidden", "safe": "yes"})
    packet = PacketMetadata.from_dict(source)
    rendered = packet.to_dict()

    assert rendered["protocol"] == "TCP"
    assert rendered["tcp_flags"] == ["SYN"]
    assert rendered["flow_key"] == "tcp|192.168.1.10|51515|203.0.113.10|443"
    assert rendered["metadata"] == {"safe": "yes"}
    assert "payload_body" not in rendered
    assert "raw_bytes" not in rendered
    assert "secret" not in json.dumps(rendered, sort_keys=True)
    json.dumps(rendered, sort_keys=True)


def test_packet_id_and_flow_key_are_deterministic():
    first = PacketMetadata.from_dict(_packet())
    second = PacketMetadata.from_dict(dict(reversed(list(_packet().items()))))

    assert first.packet_id == second.packet_id
    assert first.flow_key == second.flow_key
    assert build_flow_key(protocol="TCP", src_ip="a", src_port=1, dst_ip="b", dst_port=2) == "tcp|a|1|b|2"


def test_packet_metadata_safe_defaults_and_caller_dict_not_mutated():
    source = {"protocol": "udp", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "payload": "do-not-copy"}
    original = dict(source)

    packet = PacketMetadata.from_dict(source)

    assert source == original
    assert packet.interface == "-"
    assert packet.length == 0
    assert packet.flow_key == "udp|10.0.0.1|-|10.0.0.2|-"
    assert "payload" not in packet.to_dict()


def test_capture_session_lifecycle_transitions_are_safe():
    session = CaptureSession.create(
        interface="mock0",
        adapter="mock",
        filter_expression="tcp",
        started_at="2026-06-14T12:00:00+00:00",
    )

    running = session.transition("running", at="2026-06-14T12:00:01+00:00")
    paused = running.transition("paused")
    resumed = paused.transition("running")
    stopped = resumed.transition("stopped", at="2026-06-14T12:00:05+00:00")
    rejected = stopped.transition("running")

    assert session.status == "initialized"
    assert running.status == "running"
    assert paused.status == "paused"
    assert resumed.status == "running"
    assert stopped.status == "stopped"
    assert rejected.status == "stopped"
    assert rejected.metadata["last_transition_rejected"] == "stopped->running"


def test_session_ids_are_deterministic_for_deterministic_inputs():
    kwargs = {
        "interface": "mock0",
        "adapter": "mock",
        "filter_expression": "tcp",
        "started_at": "2026-06-14T12:00:00+00:00",
    }

    assert CaptureSession.create(**kwargs).session_id == CaptureSession.create(**kwargs).session_id


def test_filter_preset_translation_and_unsupported_validation():
    dns = build_capture_filter("dns")
    unsupported = validate_capture_filter("not-a-filter")
    unsafe = validate_capture_filter("tcp; tcpdump", mode="bpf")

    assert dns.valid is True
    assert dns.expression == "udp port 53 or tcp port 53"
    assert dns.ports == (53,)
    assert unsupported["valid"] is False
    assert unsupported["reason"] == "unsupported_filter_preset"
    assert unsafe["valid"] is False
    assert unsafe["reason"] == "unsafe_filter_expression"


def test_mock_adapter_interfaces_and_import_are_deterministic():
    adapter = MockCaptureAdapter()

    first = [packet.to_dict() for packet in adapter.import_packets("fixture")]
    second = [packet.to_dict() for packet in adapter.import_packets("fixture")]

    assert [interface["name"] for interface in adapter.list_interfaces()] == ["mock0", "mock1"]
    assert first == second
    assert first[0]["tags"] == ["fixture", "mock_import"]
    rendered = json.dumps(first, sort_keys=True)
    assert "payload_body" not in rendered
    assert "raw_bytes" not in rendered


def test_pcap_file_metadata_adapter_imports_file_metadata_only(tmp_path):
    path = tmp_path / "sample.pcap"
    path.write_bytes(b"metadata only")
    adapter = PcapFileMetadataAdapter()

    packets = adapter.import_packets(path)

    assert len(packets) == 1
    rendered = packets[0].to_dict()
    assert rendered["interface"] == "offline_file"
    assert rendered["link_type"] == "pcap_file"
    assert rendered["protocol"] == "OFFLINE"
    assert rendered["length"] == len(b"metadata only")
    assert rendered["metadata"]["parser"] == "metadata_only"


def test_pcap_file_metadata_adapter_reports_missing_file(tmp_path):
    adapter = PcapFileMetadataAdapter()

    with pytest.raises(FileNotFoundError):
        adapter.import_packets(tmp_path / "missing.pcap")


def test_capture_manager_registration_and_session_lifecycle():
    manager = CaptureManager(adapters=[MockCaptureAdapter()])

    session = manager.create_session(interface="mock0", adapter_name="mock", filter_expression="tcp")
    running = manager.start_session(session.session_id)
    paused = manager.pause_session(session.session_id)
    resumed = manager.resume_session(session.session_id)
    stopped = manager.stop_session(session.session_id)

    assert manager.list_adapters() == [{"adapter_name": "mock", "platform_support": ["darwin", "linux", "windows", "test"]}]
    assert running.status == "running"
    assert paused.status == "paused"
    assert resumed.status == "running"
    assert stopped.status == "stopped"
    assert manager.list_sessions()[0]["session_id"] == session.session_id


def test_capture_manager_add_packet_and_statistics_are_deterministic():
    manager = CaptureManager(adapters=[MockCaptureAdapter()])
    session = manager.create_session(interface="mock0", adapter_name="mock")

    added = manager.add_packet_metadata(session.session_id, _packet())
    summary = manager.session_summary(session.session_id)
    stats = manager.capture_statistics(session.session_id)

    assert added.session_id == session.session_id
    assert summary["packets_seen"] == 1
    assert summary["bytes_seen"] == 64
    assert stats["packet_count"] == 1
    assert stats["packets_per_protocol"] == {"TCP": 1}
    assert stats["packets_per_interface"] == {"mock0": 1}
    assert stats["top_ports"] == {"443": 1, "51515": 1}


def test_capture_manager_import_metadata_flow_with_mock_adapter():
    manager = CaptureManager(adapters=[MockCaptureAdapter()])

    summary = manager.import_packets(adapter_name="mock", source="fixture")

    assert summary["status"] == "imported"
    assert summary["packet_count"] == 2
    assert summary["statistics"]["flow_count"] == 2
    assert summary["statistics"]["packets_per_protocol"] == {"TCP": 1, "UDP": 1}


def test_capture_statistics_empty_input_is_safe():
    stats = summarize_packets([])

    assert stats == {
        "packet_count": 0,
        "byte_count": 0,
        "captured_byte_count": 0,
        "dropped_count": 0,
        "packets_per_protocol": {},
        "packets_per_interface": {},
        "top_talkers": {},
        "top_ports": {},
        "first_observed": "-",
        "last_observed": "-",
        "duration_seconds": 0,
        "average_packet_size": 0,
        "flow_count": 0,
    }


def test_capture_statistics_ordering_and_bounds():
    packets = [
        _packet(protocol="udp", src_port=53000, dst_port=53, length=70, observed_at="2026-06-14T12:00:01+00:00"),
        _packet(protocol="tcp", src_port=51515, dst_port=443, length=60, observed_at="2026-06-14T12:00:00+00:00"),
        _packet(protocol="tcp", src_port=51516, dst_port=443, length=90, observed_at="2026-06-14T12:00:03+00:00"),
    ]

    stats = summarize_packets(packets)

    assert list(stats["packets_per_protocol"]) == ["TCP", "UDP"]
    assert stats["top_ports"]["443"] == 2
    assert stats["first_observed"].startswith("2026-06-14T12:00:00")
    assert stats["last_observed"].startswith("2026-06-14T12:00:03")
    assert stats["duration_seconds"] == 3
    assert stats["average_packet_size"] == round((70 + 60 + 90) / 3, 2)


def test_capture_framework_does_not_call_network_or_shell(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("shell/network execution is not allowed")

    monkeypatch.setattr(subprocess, "run", fail)
    manager = CaptureManager(adapters=[MockCaptureAdapter()])

    session = manager.create_session(interface="mock0", adapter_name="mock")
    manager.start_session(session.session_id)
    manager.add_packet_metadata(session.session_id, _packet())

    assert manager.capture_statistics(session.session_id)["packet_count"] == 1


def test_repeated_identical_manager_output_is_stable():
    first = CaptureManager(adapters=[MockCaptureAdapter()]).import_packets(adapter_name="mock", source="fixture")
    second = CaptureManager(adapters=[MockCaptureAdapter()]).import_packets(adapter_name="mock", source="fixture")

    assert first == second
