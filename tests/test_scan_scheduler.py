import pytest

from core_engine.modules import scan_scheduler


def test_build_scan_plan_expands_targets_and_ports():
    plan = scan_scheduler.build_scan_plan(
        "127.0.0.0/31",
        [80, 443],
        concurrency=8,
        rate_per_second=16,
    )

    assert [target.host for target in plan.targets] == ["127.0.0.0", "127.0.0.1"]
    assert plan.ports == [80, 443]
    assert plan.total_probes == 4
    assert plan.batches == 1
    assert plan.rate_delay == pytest.approx(1 / 16)


def test_build_scan_plan_enforces_default_port_limit():
    with pytest.raises(ValueError, match="limited to 1024 ports"):
        scan_scheduler.build_scan_plan("127.0.0.1", range(1, 1030))


def test_build_scan_plan_allows_aggressive_with_warning():
    plan = scan_scheduler.build_scan_plan(
        "127.0.0.1",
        range(1, 1030),
        concurrency=128,
        rate_per_second=256,
        aggressive=True,
    )

    assert plan.aggressive is True
    assert plan.warnings == [
        "aggressive mode increases scan volume and should only be used on authorized networks"
    ]
    assert len(plan.ports) == 1029


def test_normalize_concurrency_rejects_excess_default_limit():
    with pytest.raises(ValueError, match="default limit"):
        scan_scheduler.normalize_concurrency(65)


def test_normalize_rate_rejects_excess_default_limit():
    with pytest.raises(ValueError, match="default limit"):
        scan_scheduler.normalize_rate_per_second(129)


def test_adaptive_rate_delay_increases_under_pressure():
    assert scan_scheduler.adaptive_rate_delay(base_delay=0.1, timeout_ratio=0.1) == 0.1
    assert scan_scheduler.adaptive_rate_delay(base_delay=0.1, timeout_ratio=0.3) == pytest.approx(0.15)
    assert scan_scheduler.adaptive_rate_delay(base_delay=0.1, timeout_ratio=0.6) == pytest.approx(0.2)
    assert scan_scheduler.adaptive_rate_delay(base_delay=0.1, timeout_ratio=0.8) == pytest.approx(0.4)
