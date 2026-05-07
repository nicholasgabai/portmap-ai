import socket
from types import SimpleNamespace

from core_engine import platform_utils
from core_engine.modules import scanner


def test_basic_scan_normalizes_psutil_connections(monkeypatch):
    fake_connections = [
        SimpleNamespace(
            laddr=SimpleNamespace(ip="127.0.0.1", port=8080),
            raddr=(),
            pid=123,
            status="LISTEN",
            type=socket.SOCK_STREAM,
        ),
        SimpleNamespace(
            laddr=SimpleNamespace(ip="10.0.0.10", port=5353),
            raddr=SimpleNamespace(ip="224.0.0.251", port=5353),
            pid=None,
            status="NONE",
            type=socket.SOCK_DGRAM,
        ),
    ]

    fake_psutil = SimpleNamespace(
        net_connections=lambda kind="inet": fake_connections,
        Process=lambda pid: SimpleNamespace(name=lambda: "python"),
    )
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    results = scanner.basic_scan()

    assert len(results) == 2
    assert results[0]["protocol"] in {"TCP", "UDP"}
    listen_row = next(item for item in results if item["port"] == 8080)
    assert listen_row["program"] == "python"
    assert listen_row["service_name"] == "HTTP-alt"
    assert listen_row["direction"] == "incoming"
    assert listen_row["status"] == "LISTEN"
    assert listen_row["local"] == "127.0.0.1:8080"


def test_basic_scan_falls_back_when_collection_fails(monkeypatch):
    fake_psutil = SimpleNamespace(net_connections=lambda kind="inet": (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(platform_utils, "psutil", fake_psutil)

    results = scanner.basic_scan()

    assert len(results) == 2
    assert {item["program"] for item in results} == {"dummy_app", "dummy_db"}
