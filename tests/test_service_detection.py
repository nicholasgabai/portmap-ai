import errno
import json
import socket

from core_engine.modules.ip_utils import parse_target
from core_engine.modules import service_detection


class FakeSocket:
    def __init__(self, code=0, responses=None):
        self.code = code
        self.responses = list(responses or [])
        self.sent = []
        self.closed = False
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, address):
        return self.code

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if self.responses:
            return self.responses.pop(0)
        raise socket.timeout()

    def close(self):
        self.closed = True


def socket_factory_for(fake_socket):
    def factory(family, sock_type, proto):
        assert sock_type == socket.SOCK_STREAM
        return fake_socket

    return factory


def test_load_fingerprints_from_json_file(tmp_path):
    path = tmp_path / "service_fingerprints.json"
    path.write_text(json.dumps({"services": [{"name": "Example", "default_ports": [1234]}]}))

    fingerprints = service_detection.load_fingerprints(path)

    assert fingerprints[0].name == "Example"
    assert fingerprints[0].default_ports == (1234,)


def test_normalize_service_ports_deduplicates_and_validates():
    assert service_detection.normalize_service_ports([80, "443", 80]) == [80, 443]


def test_normalize_service_ports_rejects_invalid_port():
    try:
        service_detection.normalize_service_ports([0])
    except ValueError as exc:
        assert "between 1 and 65535" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_detect_service_identifies_ssh_banner():
    fake = FakeSocket(responses=[b"SSH-2.0-OpenSSH_9.6\r\n"])

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        22,
        socket_factory=socket_factory_for(fake),
    )

    assert row["state"] == "open"
    assert row["service"] == "SSH"
    assert row["version"] == "OpenSSH_9.6"
    assert row["confidence"] >= 0.9
    assert row["evidence"] == ["banner:^SSH-"]


def test_detect_service_sends_http_head_probe():
    fake = FakeSocket(responses=[b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n"])

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        80,
        socket_factory=socket_factory_for(fake),
    )

    assert row["service"] == "HTTP"
    assert row["version"] == "nginx/1.25"
    assert row["probe"] == "http_head"
    assert fake.sent[0].startswith(b"HEAD / HTTP/1.1")


def test_detect_service_uses_tls_wrapper_for_https():
    fake = FakeSocket(responses=[b"HTTP/1.1 200 OK\r\nServer: caddy\r\n\r\n"])
    wrapped = {"called": False}

    def tls_wrapper(sock, server_hostname):
        wrapped["called"] = True
        assert server_hostname == "127.0.0.1"
        return sock

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        443,
        socket_factory=socket_factory_for(fake),
        tls_wrapper=tls_wrapper,
    )

    assert wrapped["called"] is True
    assert row["service"] == "HTTP"
    assert row["probe"] == "https_head"


def test_detect_service_returns_port_hint_for_closed_common_service():
    fake = FakeSocket(code=errno.ECONNREFUSED)

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        3389,
        socket_factory=socket_factory_for(fake),
    )

    assert row["state"] == "closed"
    assert row["service"] == "RDP"
    assert row["confidence"] == 0.25


def test_detect_service_identifies_smb_by_port_hint_when_open_without_banner():
    fake = FakeSocket(responses=[])

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        445,
        socket_factory=socket_factory_for(fake),
    )

    assert row["state"] == "open"
    assert row["service"] == "SMB"
    assert row["confidence"] == 0.55
    assert row["evidence"] == ["port_hint:445"]


def test_detect_service_identifies_mysql_banner():
    fake = FakeSocket(responses=[b"\x0a8.0.35\x00mysql_native_password\x00"])

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        3306,
        socket_factory=socket_factory_for(fake),
    )

    assert row["state"] == "open"
    assert row["service"] == "MySQL"
    assert row["version"] == "8.0.35"
    assert row["confidence"] >= 0.9


def test_detect_service_identifies_redis_error_banner():
    fake = FakeSocket(responses=[b"-NOAUTH Authentication required.\r\n"])

    row = service_detection.detect_service(
        parse_target("127.0.0.1"),
        6379,
        socket_factory=socket_factory_for(fake),
    )

    assert row["state"] == "open"
    assert row["service"] == "Redis"
    assert row["confidence"] >= 0.9


def test_enumerate_services_supports_cidr_targets():
    fake = FakeSocket(responses=[b"SSH-2.0-OpenSSH_9.6\r\n", b"SSH-2.0-OpenSSH_9.6\r\n"])

    rows = service_detection.enumerate_services(
        "127.0.0.0/31",
        ports=[22],
        socket_factory=socket_factory_for(fake),
        rate_delay=0,
    )

    assert [row["target"] for row in rows] == ["127.0.0.0", "127.0.0.1"]
    assert rows[0]["service"] == "SSH"


def test_enumerate_services_rejects_large_default_port_set():
    try:
        service_detection.enumerate_services("127.0.0.1", ports=range(1, 140))
    except ValueError as exc:
        assert "limited to 128 ports" in str(exc)
    else:
        raise AssertionError("expected ValueError")
