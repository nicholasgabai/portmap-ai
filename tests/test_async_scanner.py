import asyncio

from core_engine.modules import async_scanner
from core_engine.modules.ip_utils import parse_target
from core_engine.modules.scan_scheduler import build_scan_plan


def test_scan_with_plan_uses_async_probe_and_sorts_results():
    calls = []

    async def fake_probe(target, port, timeout):
        calls.append((target.host, port, timeout))
        await asyncio.sleep(0)
        return {
            "target": target.host,
            "port": port,
            "tcp_state": "open",
            "reason": "connect_success",
        }

    plan = build_scan_plan("127.0.0.0/31", [443, 80], concurrency=2, rate_per_second=128)

    rows = asyncio.run(async_scanner.scan_with_plan(plan, probe=fake_probe))

    assert calls
    assert [(row["target"], row["port"]) for row in rows] == [
        ("127.0.0.0", 80),
        ("127.0.0.0", 443),
        ("127.0.0.1", 80),
        ("127.0.0.1", 443),
    ]


def test_async_scan_targets_attaches_aggressive_warning():
    async def fake_probe(target, port, timeout):
        return {
            "target": target.host,
            "port": port,
            "tcp_state": "closed",
            "reason": "connection_refused",
        }

    rows = asyncio.run(
        async_scanner.async_scan_targets(
            "127.0.0.1",
            range(1, 1030),
            aggressive=True,
            concurrency=128,
            rate_per_second=256,
            probe=fake_probe,
        )
    )

    assert rows[0]["warnings"] == [
        "aggressive mode increases scan volume and should only be used on authorized networks"
    ]


def test_probe_result_shape_for_manual_result_helper():
    row = async_scanner._result(parse_target("127.0.0.1"), 80, "open", "connect_success", 1.234)

    assert row["target"] == "127.0.0.1"
    assert row["remote"] == "127.0.0.1:80"
    assert row["status"] == "OPEN"
    assert row["scanner"] == "async_connect"


def test_sync_scan_targets_wrapper(monkeypatch):
    async def fake_async_scan_targets(targets, ports, **kwargs):
        return [{"target": targets, "ports": list(ports), "kwargs": kwargs}]

    monkeypatch.setattr(async_scanner, "async_scan_targets", fake_async_scan_targets)

    rows = async_scanner.scan_targets("127.0.0.1", [80], timeout=0.1)

    assert rows == [{"target": "127.0.0.1", "ports": [80], "kwargs": {"timeout": 0.1}}]
