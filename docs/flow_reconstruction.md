# Flow Reconstruction

Phase 89 adds metadata-only bidirectional flow reconstruction from bounded packet ingestion windows.

This phase does not retain raw payload bytes, store DPI content, inject traffic, modify traffic, block traffic, open listeners, or transmit telemetry externally. It groups packet metadata into local flow/session records and topology-ready edges.

## Purpose

Flow reconstruction answers these operator questions:

- Which packet metadata records belong to the same bidirectional conversation?
- Which sessions were split by flow timeout boundaries?
- Which flows are complete, partial, or malformed?
- Which flows appear ephemeral or persistent?
- Which service is likely associated with a flow?
- Which topology edges can be inferred from observed flow metadata?
- Which flow summaries are safe for dashboard, API, topology, export, and review workflows?

## Modules

- `core_engine.telemetry.flows`
- `core_engine.telemetry.session_tracker`

The helpers reuse Phase 88 packet metadata and packet ingestion windows. They produce local-only flow records, session tracking reports, topology edge dictionaries, and dashboard/API-ready summaries.

## Flow Records

Bidirectional flow records include:

- normalized bidirectional flow key
- initiator and responder endpoints
- transport protocol
- address family
- first and last observed timestamps
- packet and byte counters
- forward and reverse packet counters
- complete, partial, or malformed classification
- ephemeral or persistent classification
- service association summary
- deterministic flow digest
- topology edge record
- source references

Output safety fields remain explicit:

- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `automatic_changes: false`
- `administrator_controlled: true`
- `local_only: true`

## Session Tracking

Session tracking records split packet metadata by bidirectional flow key and timeout boundary.

Session reports include:

- session count
- flow count
- timeout count
- complete, partial, and malformed flow counts
- topology edge counts
- flow summary
- dashboard-ready panels
- local API-compatible dictionaries

## Topology Edges

Each reconstructed flow can emit a topology-ready edge:

- source asset
- target asset
- observed-flow relationship type
- transport and service label
- observation count
- byte count
- flow reference
- confidence score

The edge is advisory evidence only. It does not trigger blocking or remediation.

## Sanitized Example

```json
{
  "record_type": "bidirectional_flow",
  "transport_protocol": "tcp",
  "classification": "complete",
  "ephemeral_or_persistent": "persistent",
  "service_association": {
    "service_name": "https",
    "service_port": 443
  },
  "topology_edge": {
    "relationship_type": "observed_flow",
    "protocol": "tcp/https"
  },
  "raw_payload_stored": false,
  "payload_bytes_stored": 0
}
```

## Operator Workflow

1. Build a Phase 88 packet ingestion window.
2. Reconstruct flow sessions with an explicit timeout.
3. Review complete, partial, malformed, and timed-out flow counters.
4. Review service association and topology edge summaries.
5. Forward metadata-only flow summaries into topology, dashboard, review, export, or later protocol phases.

## Validation Notes

Phase 89 validation uses sanitized metadata fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no packet payloads, DPI content, logs, screenshots, archives, database files, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
