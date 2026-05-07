from types import SimpleNamespace

from core_engine import network_control


def test_parse_linux_gateway():
    parsed = network_control._parse_linux_gateway("default via 192.168.1.1 dev wlan0 proto dhcp")

    assert parsed == {"gateway_ip": "192.168.1.1", "interface": "wlan0", "source": "ip route"}


def test_parse_darwin_gateway():
    output = """
       route to: default
    destination: default
        gateway: 192.168.1.1
      interface: en0
    """

    parsed = network_control._parse_darwin_gateway(output)

    assert parsed == {"gateway_ip": "192.168.1.1", "interface": "en0", "source": "route get default"}


def test_detect_default_gateway_uses_platform_command(monkeypatch):
    monkeypatch.setattr(
        network_control.platform_utils,
        "get_platform_info",
        lambda: SimpleNamespace(is_linux=True, is_macos=False, is_windows=False),
    )
    monkeypatch.setattr(network_control.platform_utils, "find_executable", lambda name: "/sbin/ip")

    def fake_run(command, check=False, capture_output=True, text=True, timeout=3):
        assert command == ["ip", "route", "show", "default"]
        return SimpleNamespace(stdout="default via 10.0.0.1 dev eth0", stderr="")

    monkeypatch.setattr(network_control.platform_utils, "run_command", fake_run)

    assert network_control.detect_default_gateway()["gateway_ip"] == "10.0.0.1"


def test_local_networks_filters_loopback(monkeypatch):
    monkeypatch.setattr(
        network_control.platform_utils,
        "network_interfaces",
        lambda: {
            "lo": [{"address": "127.0.0.1", "netmask": "255.0.0.0"}],
            "eth0": [{"address": "192.168.1.20", "netmask": "255.255.255.0"}],
        },
    )

    assert network_control.local_networks() == [
        {
            "interface": "eth0",
            "address": "192.168.1.20",
            "network": "192.168.1.0/24",
            "private": True,
        }
    ]


def test_exposed_services_ignores_loopback_and_flags_wildcard():
    rows = [
        {"program": "local", "port": 5432, "protocol": "TCP", "status": "LISTEN", "local": "127.0.0.1:5432"},
        {"program": "web", "port": 8080, "protocol": "TCP", "status": "LISTEN", "local": "0.0.0.0:8080"},
    ]

    services = network_control.exposed_services(rows)

    assert len(services) == 1
    assert services[0]["program"] == "web"
    assert services[0]["exposure"] == "all_interfaces"
    assert "all interfaces" in services[0]["recommendation"]


def test_assess_network_posture_is_advisory_only(monkeypatch):
    monkeypatch.setattr(
        network_control,
        "detect_default_gateway",
        lambda: {"gateway_ip": "192.168.1.1", "interface": "eth0", "source": "test"},
    )
    monkeypatch.setattr(network_control, "local_networks", lambda: [])

    posture = network_control.assess_network_posture([
        {"program": "ssh", "port": 22, "protocol": "TCP", "status": "LISTEN", "local": "0.0.0.0:22"}
    ])

    assert posture["advisory_only"] is True
    assert posture["automatic_changes"] is False
    assert posture["exposed_services"][0]["port"] == 22
    assert any("Review router" in item for item in posture["recommendations"])


def test_summarize_posture_includes_no_automatic_changes():
    text = network_control.summarize_posture({
        "gateway": {"gateway_ip": "192.168.1.1", "interface": "eth0"},
        "local_networks": [],
        "exposed_services": [],
        "recommendations": ["Review manually."],
    })

    assert "advisory only; no automatic changes" in text
    assert "Review manually." in text
