# Diagnostic Relay Orchestration

Phase 57 adds a bounded relay orchestration simulator for deterministic local diagnostics. It models source-to-destination forwarding workflows, records session metadata, and produces structured records for existing PortMap-AI event, storage, dashboard, policy, topology, timeline, and correlation layers.

The simulator is local-first and operator-controlled. It does not add a background service, contact external nodes, modify routers, transmit data externally, or perform active collection.

## What It Provides

- Async local relay orchestration using mock source and mock destination queues.
- Sequential forwarding with deterministic session metadata.
- Runtime limits for message count, payload size, total bytes, and duration.
- Byte accounting and throughput summaries.
- Per-frame metadata including length, entropy-style summary, printable ratio, and short hex summary.
- Structured timeout and input-limit classifications.
- Operational record builders for event, storage, timeline, topology, dashboard, policy review, and correlation systems.

## Basic Flow

```text
mock source payloads
  -> bounded relay simulation
    -> mock destination queue
      -> relay session metadata
        -> event/storage/timeline/topology/policy/correlation records
```

## Example Use

Use placeholder payloads in documentation and tests:

```python
from core_engine.diagnostics.relay_simulator import run_relay_simulation_sync

result = run_relay_simulation_sync(
    [b"sample-frame-one", b"sample-frame-two"],
    session_label="sample-relay-session",
    source_ref="mock-source",
    destination_ref="mock-destination",
    max_messages=8,
    max_payload_bytes=1024,
    max_total_bytes=8192,
    max_duration_seconds=2,
)
```

The result includes:

```json
{
  "classification": "completed",
  "diagnostic_type": "relay_orchestration",
  "message_count": 2,
  "forwarded_message_count": 2,
  "raw_payload_stored": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Integration Records

The simulator exposes helpers for platform integration:

- `build_relay_event()`
- `build_relay_finding()`
- `build_relay_storage_record()`
- `build_relay_timeline_entry()`
- `build_relay_topology_summary()`
- `build_relay_dashboard_summary()`
- `build_relay_correlation_record()`

These records are JSON serializable and do not store raw payload bytes.

## Bounds And Classifications

| Classification | Meaning |
| --- | --- |
| `completed` | Relay simulation completed within configured bounds. |
| `input_limited` | Message, payload, or total byte limits were reached. |
| `malformed` | Runtime bounds were invalid. |
| `timed_out` | Simulation exceeded the configured duration limit. |
| `unsupported` | Input payloads were not iterable or contained unsupported types. |

Non-completed classifications are marked for operator review through policy-ready records. Review records do not execute actions or change configuration.

## Dashboard And Topology Use

Dashboard layers can display forwarded message counts, forwarded byte totals, and review status. Topology layers can display the mock source-to-destination relationship as a local relay edge with source references.

## Raspberry Pi And Lightweight Runtime Notes

The simulator uses standard-library async primitives and bounded in-memory queues. Operators should keep message counts, payload sizes, and duration limits low on constrained devices. This phase does not install services or start any continuous runtime behavior.
