# Passive Interface Discovery

Phase 87 adds passive interface discovery and dry-run capture session planning records.

This module does not capture packets, store raw payloads, attempt privilege escalation, start sniffing loops, modify traffic, or transmit telemetry externally. It only normalizes local interface metadata and builds operator-selected passive capture plans.

## Purpose

Passive interface discovery answers these operator questions:

- Which local interfaces are visible to PortMap-AI?
- Which address families are present on each interface?
- Which interfaces appear loopback, broadcast-capable, multicast-capable, or link-local-only?
- Which interface would be selected for a dry-run passive capture plan?
- Does the planned interface selection fit the configured resource budget?

The output is suitable for runtime health, local API dictionaries, dashboard panels, operator visibility, and later telemetry ingestion phases.

## Modules

- `core_engine.telemetry.interfaces`
- `core_engine.telemetry.capture_sessions`

The helpers reuse platform utilities for interface metadata and existing runtime safety fields. Phase 87 does not use low-level capture APIs.

## Interface Inventory Records

Interface inventory records include:

- local interface summaries
- normalized IPv4, IPv6, and other address-family counts
- loopback classification
- broadcast and multicast capability fields
- link-local-only classification
- operator-selectable flags
- dashboard-ready rows
- local API-compatible dictionaries

Safety fields remain explicit:

- `local_only: true`
- `passive_first: true`
- `operator_controlled: true`
- `advisory_only: true`
- `capture_started: false`
- `packets_captured: 0`
- `raw_payload_stored: false`
- `privilege_escalation_attempted: false`
- `live_sniffing_loop_started: false`
- `external_transmission_enabled: false`

## Capture Session Plans

Passive capture session plans describe intended operator selections without opening a capture source.

Plan records include:

- selected interfaces
- capture target summaries
- dry-run session mode
- passive-mode enforcement
- duration and packet budgets
- resource budget status
- validation warnings
- dashboard-ready summaries
- local API-compatible dictionaries

Default Phase 87 plans use zero packet budgets and capture no traffic.

## Sanitized Example

```json
{
  "record_type": "passive_capture_session_plan",
  "session_mode": "dry-run",
  "selected_interfaces": ["interface-example"],
  "duration_seconds": 0,
  "max_packets": 0,
  "summary": {
    "passive_mode_enforced": true,
    "dry_run": true,
    "packets_captured": 0
  }
}
```

## Operator Workflow

1. Enumerate local interfaces through platform metadata.
2. Review address family and capability summaries.
3. Select an interface explicitly or accept a deterministic dry-run default.
4. Build a passive capture session plan.
5. Review resource budget status before any later ingestion phase is enabled.

Phase 87 stops at planning. Packet ingestion begins only in a later explicit phase.

## Validation Notes

Phase 87 validation uses sanitized fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no logs, packet captures, screenshots, archives, database files, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
