import errno
import socket
from types import SimpleNamespace

from core_engine import platform_utils
from core_engine.modules import discovery
from core_engine.modules.ip_utils import parse_target

MAC_A = ":".join(["aa", "bb", "cc", "dd", "ee", "ff"])
MAC_B = ":".join(["11", "22", "33", "44", "55", "66"])
MAC_C_DASHED = "-".join(["77", "88", "99", "aa", "bb", "cc"])
MAC_C = ":".join(["77", "88", "99", "aa", "bb", "cc"])


class FakeSocket:
    def __init__(self, code):
        self.code = code
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect_ex(self, address):
        return self.code

    def close(self):
        self.closed = True


def socket_factory_for(code):
    def factory(family, sock_type, proto):
        assert sock_type == socket.SOCK_STREAM
        return FakeSocket(code)

    return factory


def test_parse_arp_table_handles_common_formats():
    output = f"""
? (203.0.113.1) at {MAC_A} on en0 ifscope [ethernet]
203.0.113.20 dev wlan0 lladdr {MAC_B} REACHABLE
  203.0.113.30           {MAC_C_DASHED}     dynamic
"""

    rows = discovery.parse_arp_table(output)

    assert rows == [
        {"host": "203.0.113.1", "interface": "en0", "mac": MAC_A, "source": "arp"},
        {"host": "203.0.113.20", "interface": "wlan0", "mac": MAC_B, "source": "arp"},
        {"host": "203.0.113.30", "interface": "", "mac": MAC_C, "source": "arp"},
    ]


def test_collect_arp_inventory_uses_supplied_output():
    rows = discovery.collect_arp_inventory(
        arp_output=f"? (203.0.113.1) at {MAC_A} on en0 ifscope [ethernet]"
    )

    assert rows[0]["host"] == "203.0.113.1"
    assert rows[0]["mac"] == MAC_A


def test_tcp_reachability_treats_refused_as_reachable():
    target = parse_target("127.0.0.1")

    evidence, open_ports, closed_ports = discovery.tcp_reachability(
        target,
        [80],
        socket_factory=socket_factory_for(errno.ECONNREFUSED),
    )

    assert evidence == [
        {
            "method": "tcp",
            "port": 80,
            "reachable": True,
            "reason": "connection_refused",
            "state": "closed",
        }
    ]
    assert open_ports == []
    assert closed_ports == [80]


def test_inventory_network_assets_uses_cidr_and_arp_evidence():
    rows = discovery.inventory_network_assets(
        ["203.0.113.0/30"],
        methods=["arp"],
        arp_output=f"? (203.0.113.1) at {MAC_A} on en0 ifscope [ethernet]",
        rate_delay=0,
    )

    by_host = {row["host"]: row for row in rows}
    assert by_host["203.0.113.1"]["status"] == "reachable"
    assert by_host["203.0.113.1"]["mac"] == MAC_A
    assert by_host["203.0.113.2"]["status"] == "unknown"


def test_inventory_network_assets_uses_transport_availability():
    rows = discovery.inventory_network_assets(
        ["127.0.0.1"],
        methods=["tcp"],
        tcp_ports=[443],
        socket_factory=socket_factory_for(0),
        rate_delay=0,
    )

    assert rows[0]["status"] == "reachable"
    assert rows[0]["open_ports"] == [443]
    assert rows[0]["methods"] == ["tcp"]


def test_inventory_network_assets_marks_negative_transport_unreachable():
    rows = discovery.inventory_network_assets(
        ["192.0.2.10"],
        methods=["tcp"],
        tcp_ports=[443],
        socket_factory=socket_factory_for(errno.ETIMEDOUT),
        rate_delay=0,
    )

    assert rows[0]["status"] == "unreachable"
    assert rows[0]["evidence"][0]["reason"] == "etimedout"


def test_ping_reachability_uses_platform_ping(monkeypatch):
    monkeypatch.setattr(platform_utils, "find_executable", lambda name: f"/bin/{name}" if name == "ping" else None)
    monkeypatch.setattr(platform_utils, "get_platform_info", lambda: SimpleNamespace(is_windows=False))

    def runner(command, check=False, capture_output=True, text=True, timeout=2):
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    result = discovery.ping_reachability(parse_target("127.0.0.1"), command_runner=runner)

    assert result == {"method": "ping", "reachable": True, "reason": "ping_success"}


def test_broadcast_candidates_for_ipv4_cidr():
    assert discovery.broadcast_candidates(["203.0.113.0/24", "::1/128"]) == [
        {"broadcast": "203.0.113.255", "method": "broadcast_candidate", "network": "203.0.113.0/24"}
    ]


def test_local_topology_snapshot_is_advisory(monkeypatch):
    monkeypatch.setattr(discovery, "detect_default_gateway", lambda: {"gateway_ip": "203.0.113.1"})
    monkeypatch.setattr(
        discovery,
        "local_networks",
        lambda: [{"interface": "en0", "address": "203.0.113.10", "network": "203.0.113.0/24"}],
    )
    monkeypatch.setattr(discovery, "collect_arp_inventory", lambda: [{"host": "203.0.113.1"}])

    snapshot = discovery.local_topology_snapshot()

    assert snapshot["advisory_only"] is True
    assert snapshot["automatic_changes"] is False
    assert snapshot["broadcast_candidates"][0]["broadcast"] == "203.0.113.255"
    assert snapshot["arp_inventory"] == [{"host": "203.0.113.1"}]


def test_asset_telemetry_events_include_node_context():
    asset = {"host": "203.0.113.10", "status": "reachable"}

    events = discovery.asset_telemetry_events([asset], node_id="worker-1")

    assert events == [
        {
            "asset": asset,
            "node_id": "worker-1",
            "source": "portmap.asset_inventory",
            "target": "203.0.113.10",
            "type": "asset_inventory",
        }
    ]
