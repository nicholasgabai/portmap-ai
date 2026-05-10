import errno
import json
import socket

import pytest

from core_engine.modules import ipv6_scanner
from core_engine.modules.ip_utils import TargetAddress


class FakeTCPSocket:
    def __init__(self, code):
        self.code = code
        self.timeout = None
        self.address = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, address):
        self.address = address
        return self.code

    def close(self):
        self.closed = True


def _target(host="::1", version=6):
    return TargetAddress(host=host, version=version, source="literal", private=True, loopback=True)


def test_scan_tcp_port_supports_ipv6_success():
    fake = FakeTCPSocket(0)

    row = ipv6_scanner.scan_tcp_port(_target(), 443, socket_factory=lambda *args: fake)

    assert row["tcp_state"] == "open"
    assert row["status"] == "OPEN"
    assert row["protocol"] == "TCP"
    assert row["ip_version"] == 6
    assert row["remote"] == "[::1]:443"
    assert fake.address == ("::1", 443, 0, 0)
    assert fake.closed is True
    json.dumps(row)


def test_scan_tcp_port_marks_refused_closed():
    fake = FakeTCPSocket(errno.ECONNREFUSED)

    row = ipv6_scanner.scan_tcp_port(_target("127.0.0.1", 4), 22, socket_factory=lambda *args: fake)

    assert row["tcp_state"] == "closed"
    assert row["reason"] == "connection_refused"
    assert row["remote"] == "127.0.0.1:22"
    assert fake.address == ("127.0.0.1", 22)


def test_scan_tcp_port_marks_timeout_filtered():
    fake = FakeTCPSocket(errno.ETIMEDOUT)

    row = ipv6_scanner.scan_tcp_port(_target(), 443, socket_factory=lambda *args: fake)

    assert row["tcp_state"] == "filtered"
    assert row["reason"] == "etimedout"


def test_scan_dual_stack_targets_filters_to_ipv6(monkeypatch):
    targets = [
        TargetAddress("127.0.0.1", 4, "literal", True, True),
        TargetAddress("::1", 6, "literal", True, True),
    ]
    monkeypatch.setattr(ipv6_scanner, "expand_targets", lambda *args, **kwargs: [target for target in targets if target.version == 6])
    sockets = [FakeTCPSocket(0), FakeTCPSocket(errno.ECONNREFUSED)]

    rows = ipv6_scanner.scan_dual_stack_targets(
        ["127.0.0.1", "::1"],
        [80, 443],
        ip_version="6",
        rate_delay=0,
        socket_factory=lambda *args: sockets.pop(0),
    )

    assert [row["remote"] for row in rows] == ["[::1]:80", "[::1]:443"]
    assert [row["tcp_state"] for row in rows] == ["open", "closed"]


def test_scan_dual_stack_targets_enforces_port_limit():
    with pytest.raises(ValueError, match="limited to 1 ports"):
        ipv6_scanner.scan_dual_stack_targets("127.0.0.1", [80, 443], max_ports=1)


def test_invalid_tcp_ports_are_rejected():
    with pytest.raises(ValueError, match="between 1 and 65535"):
        ipv6_scanner.normalize_tcp_ports([70000])
