import json
import logging

import pytest

from core_engine import worker_node
from core_engine.telemetry_framing import (
    TelemetryFrameMalformed,
    TelemetryFrameTooLarge,
    encode_json_frame,
    read_json_frames,
    telemetry_frame_error_summary,
)


class ChunkedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeout = None
        self.sent = b""
        self.closed = False

    def recv(self, size):
        if self.chunks:
            chunk = self.chunks.pop(0)
            if len(chunk) > size:
                self.chunks.insert(0, chunk[size:])
                return chunk[:size]
            return chunk
        return b""

    def sendall(self, data):
        self.sent += data

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def close(self):
        self.closed = True


def _payload(**extra):
    payload = {
        "node_id": "worker-fixture",
        "score": 0.42,
        "ports": [
            {
                "program": "Unknown",
                "service_name": "Unattributed",
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "local": "local-placeholder:51515",
                "remote": "remote-placeholder:443",
                "source_mode": "live",
            }
        ],
        "milestone_v_counters": {
            "observations_seen": 1,
            "sessions_reconstructed": 1,
            "flows_reconstructed": 1,
            "relationship_edges": 1,
            "topology_records": 1,
        },
    }
    payload.update(extra)
    return payload


def test_large_worker_payload_over_64kb_decodes_from_partial_tcp_reads():
    ports = []
    for idx in range(180):
        ports.append(
            {
                "program": "Unknown",
                "service_name": "Unattributed",
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "local": f"local-placeholder:{50000 + idx}",
                "remote": "remote-placeholder:443",
                "source_mode": "live",
                "metadata_padding": "x" * 420,
            }
        )
    payload = _payload(ports=ports)
    frame = encode_json_frame(payload)
    assert len(frame) > 65536

    decoded = read_json_frames(ChunkedSocket([frame[:17], frame[17:60000], frame[60000:]]))

    assert decoded == [payload]
    assert decoded[0]["milestone_v_counters"]["flows_reconstructed"] == 1


def test_partial_tcp_reads_reconstruct_complete_framed_json():
    payload = _payload()
    frame = encode_json_frame(payload)

    decoded = read_json_frames(ChunkedSocket([frame[:5], frame[5:25], frame[25:]]))

    assert decoded == [payload]


def test_multiple_newline_frames_do_not_merge():
    first = _payload(node_id="worker-one", score=0.1)
    second = _payload(node_id="worker-two", score=0.2)

    decoded = read_json_frames(ChunkedSocket([encode_json_frame(first) + encode_json_frame(second)]))

    assert [row["node_id"] for row in decoded] == ["worker-one", "worker-two"]
    assert [row["score"] for row in decoded] == [0.1, 0.2]


def test_existing_small_legacy_payload_without_newline_still_decodes():
    payload = _payload()

    decoded = read_json_frames(ChunkedSocket([json.dumps(payload).encode("utf-8")]))

    assert decoded == [payload]


def test_malformed_json_frame_raises_sanitized_error_summary():
    with pytest.raises(TelemetryFrameMalformed) as excinfo:
        read_json_frames(ChunkedSocket([b'{"local":"local-placeholder:443","bad":', b"\n"]))

    summary = telemetry_frame_error_summary(excinfo.value)
    assert summary["reason"] == "malformed_frame"
    assert summary["raw_payload_logged"] is False
    assert "local-placeholder" not in json.dumps(summary)


def test_oversized_frame_is_rejected_safely():
    payload = _payload(ports=[{"metadata_padding": "x" * 64}])

    with pytest.raises(TelemetryFrameTooLarge):
        encode_json_frame(payload, max_frame_bytes=32)

    with pytest.raises(TelemetryFrameTooLarge):
        read_json_frames(ChunkedSocket([b'{"padding":"' + (b"x" * 64) + b'"}\n']), max_frame_bytes=32)


def test_worker_send_to_master_sends_complete_framed_payload(monkeypatch):
    sent_socket = ChunkedSocket([json.dumps({"status": "ok"}).encode("utf-8")])
    payload = _payload()

    monkeypatch.setattr(worker_node, "collect_connections", lambda logger: [])
    monkeypatch.setattr(worker_node, "build_payload", lambda node_id, connections, logger, autolearn: payload)
    monkeypatch.setattr(worker_node.socket, "create_connection", lambda endpoint, timeout: sent_socket)

    worker_node.send_to_master(
        "worker-fixture",
        "127.0.0.1",
        9000,
        1,
        logging.getLogger("test.worker.framing"),
        autolearn=False,
    )

    assert sent_socket.sent.endswith(b"\n")
    assert read_json_frames(ChunkedSocket([sent_socket.sent])) == [payload]


def test_milestone_v_telemetry_fields_survive_transport():
    payload = _payload(
        flows=[{"record_type": "flow_event", "source_mode": "live"}],
        topology_edges=[{"record_type": "topology_edge", "source_mode": "live"}],
    )

    decoded = read_json_frames(ChunkedSocket([encode_json_frame(payload)]))[0]

    assert decoded["milestone_v_counters"]["observations_seen"] == 1
    assert decoded["flows"][0]["source_mode"] == "live"
    assert decoded["topology_edges"][0]["source_mode"] == "live"
