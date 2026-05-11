import json

from core_engine.modules import os_fingerprint


def test_load_os_fingerprints_from_json_file(tmp_path):
    path = tmp_path / "os_fingerprints.json"
    path.write_text(json.dumps({"families": [{"name": "ExampleOS", "ttl_initial": [64]}]}))

    fingerprints = os_fingerprint.load_os_fingerprints(path)

    assert fingerprints[0].name == "ExampleOS"
    assert fingerprints[0].ttl_initial == (64,)


def test_fingerprint_observation_identifies_windows_from_rdp_and_ttl():
    result = os_fingerprint.fingerprint_observation(
        {
            "target": "203.0.113.20",
            "ttl": 127,
            "tcp_window": 64240,
            "tcp_options": ["mss", "sack", "wscale"],
            "services": [{"service": "RDP"}, {"service": "SMB"}],
            "banners": ["Microsoft-IIS/10.0"],
        }
    )

    assert result["probable_os"] == "Windows"
    assert result["confidence"] >= 0.8
    assert any("services:RDP,SMB" in item for item in result["evidence"])


def test_fingerprint_observation_identifies_linux_from_ssh_banner():
    result = os_fingerprint.fingerprint_observation(
        {
            "target": "203.0.113.5",
            "ttl": 63,
            "tcp_window": 29200,
            "tcp_options": "mss,sack,timestamp,wscale",
            "service_results": [
                {
                    "service": "SSH",
                    "banner": "SSH-2.0-OpenSSH_9.6 Ubuntu",
                    "version": "OpenSSH_9.6 Ubuntu",
                }
            ],
        }
    )

    assert result["probable_os"] == "Linux"
    assert result["confidence"] >= 0.7
    assert "banner:OpenSSH" in result["evidence"]


def test_fingerprint_observation_reports_unknown_when_confidence_low():
    result = os_fingerprint.fingerprint_observation({"target": "198.51.100.10", "services": ["HTTP"]})

    assert result["probable_os"] == "unknown"
    assert result["confidence"] == 0.0
    assert result["evidence"] == []
    assert result["candidates"]


def test_fingerprint_from_service_results_merges_active_evidence():
    result = os_fingerprint.fingerprint_from_service_results(
        "router.local",
        [{"service": "SNMP", "banner": "MikroTik RouterOS"}],
        ttl=254,
    )

    assert result["probable_os"] == "network_appliance"
    assert result["confidence"] >= 0.6


def test_fingerprint_targets_uses_service_enumeration(monkeypatch):
    def fake_enumerate_services(
        targets,
        ports=None,
        ip_version="auto",
        timeout=2.0,
        max_targets=64,
        max_ports=128,
        aggressive=False,
    ):
        assert targets == "127.0.0.1"
        assert ports == [22]
        assert ip_version == "4"
        assert timeout == 0.1
        assert aggressive is True
        return [
            {
                "target": "127.0.0.1",
                "service": "SSH",
                "banner": "SSH-2.0-OpenSSH_9.6 Debian",
                "version": "OpenSSH_9.6 Debian",
            }
        ]

    monkeypatch.setattr(os_fingerprint, "enumerate_services", fake_enumerate_services)

    rows = os_fingerprint.fingerprint_targets(
        "127.0.0.1",
        ports=[22],
        ip_version="4",
        timeout=0.1,
        aggressive=True,
        ttl=64,
    )

    assert rows[0]["target"] == "127.0.0.1"
    assert rows[0]["probable_os"] == "Linux"
    assert rows[0]["service_results"][0]["service"] == "SSH"
