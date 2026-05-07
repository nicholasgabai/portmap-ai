# TUI Dashboard

Phase 10 makes the Textual dashboard usable as the primary local operator surface.

Run it with:

```bash
portmap tui
```

or let the stack launcher start it:

```bash
portmap stack --verbose
```

## Panels

- Node Overview: registered nodes, role, status, and last heartbeat.
- Metrics: node counts, last heartbeat, remediation totals, firewall mode, orchestrator health, and API counters.
- Scan Results: latest sampled ports, risk score, AI provider, and scoring signals from worker telemetry.
- Remediation Feed: recent remediation decisions with action, enforcement mode, reason, score, and signals.
- Expected Services: observed candidate services and configured allowlisted services.
- Command Outcomes: worker command audit events such as received, applied, failed, or ignored.
- Master Log Tail: recent master-node runtime log lines.

## Controls

- Scan Now: queues a `scan_now` command for the selected node.
- Toggle Autolearn: queues a `set_autolearn` command for the selected node.
- Detect Orchestrator: probes the configured/local orchestrator health endpoint.
- Export Logs: creates the same audit bundle as `portmap logs`.
- Allowlist Selected: adds the selected observed service to `expected_services`.
- Remove Allowlist: removes the selected expected service.
- Tail: cycles displayed row count for scan, remediation, command, and log panels.

Keyboard shortcuts:

- `?` opens the help modal.
- `e` exports logs.

## Data Sources

The dashboard reads local runtime state and logs:

- `~/.portmap-ai/data/orchestrator_state.json`
- `~/.portmap-ai/logs/master_events.log`
- `~/.portmap-ai/logs/remediation_events.jsonl`
- `~/.portmap-ai/logs/command_events.jsonl`
- `~/.portmap-ai/logs/master.log`

It also checks the configured orchestrator `/healthz` and `/metrics` endpoints when refreshing.
