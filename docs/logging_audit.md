# Logging and Audit

Phase 6 standardizes PortMap-AI audit records as JSON Lines files under `~/.portmap-ai/logs`.

Primary audit files:

- `audit_events.jsonl` - normalized cross-component audit stream.
- `command_events.jsonl` - worker command receipt/outcome records.
- `remediation_events.jsonl` - remediation decisions and enforcement context.
- `master_events.log` - worker telemetry snapshots written as JSON lines.

Common normalized fields:

- `timestamp` - UTC ISO-8601 timestamp ending in `Z`.
- `event_type` - stable event category, such as `command_event` or `remediation_decision`.
- `node_id` - node involved in the event when available.
- `action` - command or remediation action when applicable.
- `status` - event outcome, such as `received`, `applied`, `failed`, `ignored`, or `decided`.
- `risk_score` - risk/remediation score when applicable.
- `source` - component that emitted the normalized event.
- `details` - source-specific structured payload.

Current event coverage:

- Worker and background-agent command events are written to `command_events.jsonl` and mirrored into `audit_events.jsonl`.
- Remediation decisions are written to `remediation_events.jsonl` and mirrored into `audit_events.jsonl`.
- Master worker telemetry snapshots include `event_type`, `timestamp`, `node_id`, `risk_score`, sampled ports, anomalies, and score factors.

Export logs:

```bash
portmap logs --output-dir ./artifacts
portmap-export-logs --output-dir ./artifacts
```

Filter audit events without creating an archive:

```bash
portmap logs --filter-node worker-001 --tail 20
portmap logs --filter-event-type remediation_decision
portmap-export-logs --filter-event-type command_event --tail 10
```

Archives include `.log`, rotated `.log.*`, `.jsonl`, and state `.json` files unless `--no-state` is passed.
