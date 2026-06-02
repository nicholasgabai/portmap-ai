# Live Scan Snapshot Deduplication

This pre-Milestone U hardening fix keeps worker scan payloads as fresh, bounded snapshots of current live observations. It prevents live TUI, scoring, remediation, dashboard, API, and export-safe summaries from treating stale or duplicate socket rows as an ever-growing list of current ports.

## Live Snapshot Versus Historical Intelligence

Live scan snapshots represent the current scan cycle only. They are not historical storage.

Historical behavior remains handled by the dedicated baseline, snapshot, replay, retention, and long-term intelligence modules. Those modules may retain metadata-only summaries over time, but live worker payloads and TUI scan rows should not accumulate stale observations across intervals.

## Snapshot Deduplication

Each live scan cycle normalizes observations into a stable metadata key using:

- node identifier
- local address class
- local port
- remote address class when present
- remote port when present
- protocol
- status or state
- process, service, or app attribution
- source mode

Duplicate rows collapse into one current observation. The snapshot is bounded before scoring, master logging, remediation review, and TUI rendering.

## Stale And Transient Socket Handling

Live scan snapshots prune transient socket states such as `TIME_WAIT` by default. This keeps short-lived stale socket observations from carrying forward as current TUI rows or repeated scoring inputs. The baseline and historical intelligence modules remain the correct place to summarize recurring or long-term behavior.

## Operator View Protection

The TUI scan-results panel now reads the latest current snapshot per node instead of combining multiple prior telemetry events as if they were still current. This keeps the operator view aligned with the latest worker scan cycle.

Source labeling remains intact:

- `live` rows represent current live observations.
- `fixture` and `simulated` rows may use deterministic dummy labels.
- `replay` rows come from bounded historical replay.
- `unknown` rows are incomplete or malformed source records.

`dummy_app` and `dummy_db` remain restricted to explicit `fixture` or `simulated` mode and do not appear in live/default rows.

## Safety Boundary

This fix is metadata-only and advisory. It does not store packet payloads, capture credentials, modify firewall rules, install services, change router settings, or perform remediation automatically. Remediation remains dry-run safe unless the operator explicitly enables an approved enforcement mode.
