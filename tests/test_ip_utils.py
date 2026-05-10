import socket

import pytest

from core_engine.modules import ip_utils


def test_parse_target_accepts_ipv4_and_ipv6_literals():
    ipv4 = ip_utils.parse_target("127.0.0.1")
    ipv6 = ip_utils.parse_target("[::1]")

    assert ipv4.version == 4
    assert ipv4.loopback is True
    assert ipv6.version == 6
    assert ipv6.host == "::1"


def test_expand_cidr_enforces_safe_limit():
    with pytest.raises(ValueError, match="limit is 2"):
        ip_utils.expand_cidr("192.0.2.0/29", max_targets=2)


def test_expand_targets_filters_ip_version():
    targets = ip_utils.expand_targets(["127.0.0.1", "::1"], ip_version="6")

    assert len(targets) == 1
    assert targets[0].host == "::1"


def test_resolve_hostname_dedupes_addresses(monkeypatch):
    monkeypatch.setattr(
        ip_utils.socket,
        "getaddrinfo",
        lambda hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 0, 0, 0)),
        ],
    )

    targets = ip_utils.resolve_hostname("localhost")

    assert [target.host for target in targets] == ["127.0.0.1", "::1"]
    assert {target.source for target in targets} == {"dns"}


def test_invalid_targets_are_rejected_without_dns():
    with pytest.raises(ValueError, match="Invalid IP address"):
        ip_utils.expand_targets("not a host", resolve_names=False)


def test_format_host_port_brackets_ipv6():
    assert ip_utils.format_host_port("127.0.0.1", 443) == "127.0.0.1:443"
    assert ip_utils.format_host_port("::1", 443) == "[::1]:443"
