# TUI Dashboard

Phase 10 made the Textual dashboard usable as the primary local operator surface. Phase 170.5 adds multi-tab navigation so future operator-visible systems can be validated without overcrowding the existing dashboard. Phase 170.5A fills the Risk tab with read-only risk and remediation status from existing dashboard runtime data.

Run it with:

```bash
portmap tui
```

or let the stack launcher start it:

```bash
portmap stack --verbose
```

## Panels

The Dashboard tab remains the default screen and preserves the existing live runtime panels:

- Node Overview: registered nodes, role, status, and last heartbeat.
- Metrics: node counts, last heartbeat, remediation totals, firewall mode, orchestrator health, and API counters.
- Scan Results: latest sampled ports, source mode, risk score, AI provider, and scoring signals from worker telemetry.
- Remediation Feed: recent remediation decisions with action, enforcement mode, reason, score, and signals.
- Expected Services: observed candidate services and configured allowlisted services.
- Command Outcomes: worker command audit events such as received, applied, failed, or ignored.
- Master Log Tail: recent master-node runtime log lines.

## Tabs

The TUI provides seven tabs. Dashboard remains the default live runtime view, Risk now provides read-only live risk visibility, and the remaining tabs are safe readiness placeholders for future operator surfaces.

- `1` Dashboard: current live runtime dashboard and default launch screen.
- `2` Risk: live read-only risk summary, top signals, remediation feed, risk timeline, allowlist status, and safety boundary.
- `3` Exports: Last Export Summary, export validation status, export destination, and future Runtime Export Validation Panel.
- `4` Governance: Audit Logging, Compliance Profiles, Data Governance, Operator Accountability, Security Reviews, and Privacy Safeguards.
- `5` Deployment: Windows installer, macOS packaging, Linux packaging, container deployment, secure updater, and deployment wizard readiness.
- `6` AI: future Milestone AC AI evolution readiness.
- `7` Packet: future Milestone AE Packet Intelligence placeholder.

The Risk tab is display-only. It uses the same sampled ports, remediation preview feed, risk timeline, and allowlist candidate data already available to Dashboard refreshes. It does not execute remediation, block traffic, mutate allowlists beyond existing footer actions, modify firewall/process/service state, add collectors, or start packet capture.

The Packet tab is navigation infrastructure only until Milestone AE. It does not start packet capture, protocol inspection, collectors, or network activity.

## Controls

- Scan Now: queues a `scan_now` command for the selected node.
- Toggle Autolearn: queues a `set_autolearn` command for the selected node.
- Detect Orchestrator: probes the configured/local orchestrator health endpoint.
- Export Logs: creates the same audit bundle as `portmap logs`.
- Allowlist Selected: adds the selected observed service to `expected_services`.
- Remove Allowlist: removes the selected expected service.
- Tail: cycles displayed row count for scan, remediation, command, and log panels.

Keyboard shortcuts:

- `1` opens Dashboard.
- `2` opens Risk.
- `3` opens Exports.
- `4` opens Governance.
- `5` opens Deployment.
- `6` opens AI.
- `7` opens Packet.
- `?` opens the help modal.
- `e` exports logs.

Switching tabs does not stop dashboard refresh loops. Existing Dashboard data continues to update while Risk or placeholder tabs are visible.

## Phase 170.5 Bridge

Phase 170.5 sits between Milestone AB Compliance And Governance and Milestone AC AI Intelligence Evolution. It adds the navigation foundation before new operator-visible AI, governance, export validation, deployment, or packet-intelligence views are added.

The Export Validation Panel remains future work under the Exports tab. Governance, Deployment, and AI tabs are readiness surfaces until later phases attach live models. Packet remains a placeholder until future Milestone AE Packet Intelligence And Deep Visibility.

## Phase 170.5A Risk Dashboard Tab

Phase 170.5A replaces the Risk placeholder text with a read-only risk dashboard backed by existing runtime data already loaded by the Dashboard refresh loop.

The Risk tab shows:

- Risk Summary: current findings, monitor/review/block queue counts, latest/max/average score, latest update, anomaly count, and provider/model summary when available.
- Top Risk Signals: recent sampled-port and remediation signals such as `risky_port`, `sensitive_port`, `listening_socket`, and `unknown_service`, sanitized and truncated for display.
- Recent Remediation Feed: latest remediation preview actions, enforcement mode, reason, score, and short signal summary.
- Risk Timeline: recent score buckets with event count, average score, max score, and monitor/review/block counts.
- Allowlist Status: observed candidates, configured allowlisted services, selected candidate, and a reminder to use existing footer actions for mutations.
- Safety Boundary: read-only status, no enforcement, no blocking, no remediation execution, no firewall/process/service changes, no packet capture, and no new collectors.

Future 170.5B-G work can fill Exports, Governance, Deployment, AI, Packet, and related tab surfaces as dedicated views rather than crowding the Dashboard tab.

Safety boundaries:

- No packet capture implementation.
- No new runtime collectors.
- No new network behavior.
- No new export file writes beyond the existing Export Logs action.
- No governance enforcement.
- No installer or deployment execution.
- No runtime stack behavior changes.

## Data Sources

The dashboard reads local runtime state and logs:

- `~/.portmap-ai/data/orchestrator_state.json`
- `~/.portmap-ai/logs/master_events.log`
- `~/.portmap-ai/logs/remediation_events.jsonl`
- `~/.portmap-ai/logs/command_events.jsonl`
- `~/.portmap-ai/logs/master.log`

It also checks the configured orchestrator `/healthz` and `/metrics` endpoints when refreshing.

## Source Labels

TUI scan-result rows include source labels so operators can distinguish live observations from demo, fixture, replay, or unknown records. Live/default runtime rows do not display `dummy_app` or `dummy_db`; unresolved live process attribution is shown as `Unattributed` or `Unknown`. Dummy labels are reserved for explicit `simulated` or `fixture` mode.

See `docs/source_mode_labeling.md` for the shared source-mode rules used by TUI, dashboard, API, and export-safe telemetry summaries.
