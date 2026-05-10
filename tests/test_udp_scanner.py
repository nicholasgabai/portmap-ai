import errno
import json
import socket

import pytest

from core_engine.modules import udp_scanner


class FakeUDPSocket:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.sent = 0
        self.closed = False
        self.timeout = None
        self.address = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def send(self, payload):
        self.sent += 1
        return len(payload)

    def recv(self, size):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


def _fake_resolve(monkeypatch):
    monkeypatch.setattr(
        udp_scanner.socket,
        "getaddrinfo",
        lambda target, port, type=socket.SOCK_DGRAM: [
            (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (target, port))
        ],
    )


def test_common_udp_probes_cover_required_services():
    probes = udp_scanner.COMMON_UDP_PROBES

    assert {53, 67, 68, 123, 137, 138, 161, 5353}.issubset(probes)
    assert probes[53].name == "DNS"
    assert probes[123].payload


def test_scan_udp_port_marks_response_open(monkeypatch):
    _fake_resolve(monkeypatch)
    fake = FakeUDPSocket([b"response"])

    row = udp_scanner.scan_udp_port("127.0.0.1", 53, socket_factory=lambda *args: fake)

    assert row["udp_state"] == "open"
    assert row["status"] == "OPEN"
    assert row["protocol"] == "UDP"
    assert row["port"] == 53
    assert row["probe"] == "DNS"
    assert row["response_bytes"] == len(b"response")
    assert fake.sent == 1
    assert fake.closed is True
    json.dumps(row)


def test_scan_udp_port_marks_connection_refused_closed(monkeypatch):
    _fake_resolve(monkeypatch)
    fake = FakeUDPSocket([ConnectionRefusedError(errno.ECONNREFUSED, "refused")])

    row = udp_scanner.scan_udp_port("127.0.0.1", 161, retries=3, socket_factory=lambda *args: fake)

    assert row["udp_state"] == "closed"
    assert row["reason"] == "icmp_unreachable"
    assert row["attempts"] == 1


def test_scan_udp_port_retries_timeouts_and_marks_filtered(monkeypatch):
    _fake_resolve(monkeypatch)
    fake = FakeUDPSocket([socket.timeout("first"), socket.timeout("second")])

    row = udp_scanner.scan_udp_port("127.0.0.1", 123, retries=1, socket_factory=lambda *args: fake)

    assert row["udp_state"] == "filtered"
    assert row["reason"] == "timeout"
    assert row["attempts"] == 2
    assert fake.sent == 2


def test_scan_udp_port_marks_permission_errors_unknown(monkeypatch):
    _fake_resolve(monkeypatch)
    fake = FakeUDPSocket([PermissionError(errno.EPERM, "blocked")])

    row = udp_scanner.scan_udp_port("127.0.0.1", 5353, socket_factory=lambda *args: fake)

    assert row["udp_state"] == "unknown"
    assert row["reason"] == "permission_denied"


def test_scan_udp_target_enforces_safe_port_limit(monkeypatch):
    _fake_resolve(monkeypatch)

    with pytest.raises(ValueError, match="limited to 2 ports"):
        udp_scanner.scan_udp_target("127.0.0.1", [53, 123, 161], max_ports=2)


def test_scan_udp_target_scans_multiple_ports_without_sleep(monkeypatch):
    _fake_resolve(monkeypatch)
    sockets = [FakeUDPSocket([b"dns"]), FakeUDPSocket([socket.timeout("ntp")])]

    rows = udp_scanner.scan_udp_target(
        "127.0.0.1",
        [53, 123],
        retries=0,
        rate_delay=0,
        socket_factory=lambda *args: sockets.pop(0),
    )

    assert [row["port"] for row in rows] == [53, 123]
    assert [row["udp_state"] for row in rows] == ["open", "filtered"]


def test_invalid_udp_ports_are_rejected():
    with pytest.raises(ValueError, match="between 1 and 65535"):
        udp_scanner.normalize_udp_ports([0])
