import pytest

from core_engine.events import (
    EventValidationError,
    LocalEventBus,
    LocalEventQueue,
    create_event,
    event_from_dict,
    event_from_json,
    event_to_dict,
    event_to_json,
)


def test_event_creation_sets_defaults_and_references():
    event = create_event(
        "asset_observed",
        severity="low",
        source="visibility",
        message="Sample asset observed",
        asset_ref="asset-sample",
        metadata={"source": "sample"},
    )

    assert event.event_id.startswith("evt-")
    assert event.event_type == "asset_observed"
    assert event.asset_ref == "asset-sample"
    assert event.metadata == {"source": "sample"}
    assert event.raw_payload_stored is False
    assert event.automatic_changes is False
    assert event.administrator_controlled is True


def test_invalid_event_type_is_rejected():
    with pytest.raises(EventValidationError):
        create_event("unexpected_event", source="test", message="Sample")


def test_invalid_severity_is_rejected():
    with pytest.raises(EventValidationError):
        create_event("system_notice", severity="urgent", source="test", message="Sample")


def test_serialization_round_trip_preserves_event():
    event = create_event(
        "service_observed",
        severity="medium",
        source="service_metadata",
        message="Sample service metadata observed",
        service_ref="service-sample",
        metadata={"port": 8443},
    )

    payload = event_to_dict(event)
    assert event_from_dict(payload).to_dict() == payload
    assert event_from_json(event_to_json(event)).to_dict() == payload


def test_malformed_event_payload_is_rejected_safely():
    with pytest.raises(EventValidationError):
        event_from_dict({"event_type": "system_notice"})

    event = create_event("system_notice", source="test", message="Sample", metadata={"bad": object()})
    with pytest.raises(EventValidationError):
        event_to_json(event)


def test_queue_preserves_fifo_order():
    first = create_event("runtime_health", source="runtime", message="First heartbeat")
    second = create_event("system_notice", source="runtime", message="Second notice")
    queue = LocalEventQueue()

    queue.enqueue(first)
    queue.enqueue(second)

    assert queue.consume() == first
    assert queue.consume() == second
    assert queue.consume() is None


def test_bus_publish_subscribe_consume_and_unsubscribe():
    received = []
    bus = LocalEventBus()
    subscription_id = bus.subscribe(received.append, event_type="snapshot_created")
    ignored = create_event("runtime_health", source="runtime", message="Heartbeat")
    matched = create_event("snapshot_created", source="visibility", message="Snapshot created")

    assert bus.publish(ignored) == []
    results = bus.publish(matched)

    assert len(results) == 1
    assert results[0].ok is True
    assert received == [matched]
    assert bus.consume() == [ignored, matched]
    assert bus.unsubscribe(subscription_id) is True
    assert bus.unsubscribe(subscription_id) is False


def test_bus_handler_failure_is_isolated():
    received = []
    bus = LocalEventBus()

    def failing_handler(event):
        raise RuntimeError("sample handler failure")

    bus.subscribe(failing_handler)
    bus.subscribe(received.append)
    event = create_event("baseline_delta_detected", severity="high", source="visibility", message="Sample delta")

    results = bus.publish(event)

    assert [result.ok for result in results] == [False, True]
    assert "sample handler failure" in (results[0].error or "")
    assert received == [event]


def test_bus_replay_uses_history_without_external_transport():
    replayed = []
    bus = LocalEventBus(history_limit=2)
    first = create_event("asset_observed", source="visibility", message="First")
    second = create_event("flow_observed", source="flows", message="Second")
    third = create_event("policy_review_required", source="policy", message="Third")

    bus.publish(first)
    bus.publish(second)
    bus.publish(third)
    results = bus.replay(replayed.append)

    assert [event.message for event in replayed] == ["Second", "Third"]
    assert all(result.ok for result in results)
