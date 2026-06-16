# TUI Dashboard

Phase 10 made the Textual dashboard usable as the primary local operator surface. Phase 170.5 adds multi-tab navigation so future operator-visible systems can be validated without overcrowding the existing dashboard. Phase 170.5A fills the Risk tab with read-only risk and remediation status from existing dashboard runtime data, Phase 170.5A.1 refines the split so Dashboard stays high-level while Risk owns detailed risk/remediation review, Phase 170.5A.2 turns Risk into a structured workspace layout, Phase 170.5A.3 makes Risk an investigation workspace centered on active findings, Phase 170.5A.4 aligns Risk styling with the dense Dashboard presentation, and Phase 170.5A.5 keeps Risk compact enough for a one-screen operator view.

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
- Risk Overview: compact latest score, max score, monitor/review/block queue counts, latest update timestamp, and a shortcut reminder for the Risk tab.
- Scan Results: latest sampled ports, source mode, risk score, AI provider, and scoring signals from worker telemetry.
- Expected Services: observed candidate services and configured allowlisted services.
- Topology Edges: passive flow relationships when flow telemetry exists.
- Traffic Flows: bidirectional flow summaries with packet and byte counts, no raw payload storage.
- Command Outcomes: worker command audit events such as received, applied, failed, or ignored.
- Master Log Tail: recent master-node runtime log lines.

Dashboard intentionally does not show the full remediation feed or full risk timeline when the Risk tab is available. Press `2` for detailed risk/remediation review.

## Tabs

The TUI provides seven tabs. Dashboard remains the default live runtime view, Risk now provides read-only live risk visibility, and the remaining tabs are safe readiness placeholders for future operator surfaces.

- `1` Dashboard: current live runtime dashboard and default launch screen.
- `2` Risk: one-screen live read-only risk investigation dashboard with summary, queue counts, active findings, top signals, remediation feed, risk timeline, and allowlist/safety footer.
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

The Risk tab is the detailed risk/remediation workspace. It shows:

- Risk Summary: current findings, latest/max/average score, latest update, anomaly count, and provider/model summary when available.
- Queue Summary: monitor, review, block, and total queue/event counts.
- Active Risk Findings: primary investigation panel combining current sampled-port and remediation findings from existing runtime data, sorted by score and recency.
- Top Risk Signals: recent sampled-port and remediation signals such as `risky_port`, `sensitive_port`, `listening_socket`, and `unknown_service`, sanitized and truncated for display.
- Recent Remediation Feed: compact table-like rows with timestamp, action, enforcement mode, score, short reason, and signal summary.
- Risk Timeline: compact table-like score buckets with event count, average score, max score, and monitor/review/block counts.
- Allowlist Status: observed candidates, configured allowlisted services, selected candidate, and a reminder to use existing footer actions for mutations.
- Safety Boundary: read-only status, no enforcement, no blocking, no remediation execution, no firewall/process/service changes, no packet capture, and no new collectors.

Future 170.5B-G work can fill Exports, Governance, Deployment, AI, Packet, and related tab surfaces as dedicated views rather than crowding the Dashboard tab.

## Phase 170.5A.1 Risk Dashboard Refinement

Phase 170.5A.1 makes Risk the primary risk/remediation workspace and reduces duplicated risk detail on Dashboard. Dashboard remains shortcut `1` and the default overview with compact risk status only. Risk remains shortcut `2` and owns detailed summaries, queue counts, top signals, remediation feed, risk timeline, allowlist status, and safety text.

This refinement is display-only. It does not change runtime behavior, add collectors, write files, capture packets, execute remediation, block traffic, enforce policies, or modify firewall/process/service state. It is the bridge before Phase 170.5B Exports Dashboard work.

## Phase 170.5A.2 Risk Workspace Layout Refinement

Phase 170.5A.2 changes Risk from a single-column text report into a full-screen operator workspace. The live data remains the same existing Dashboard refresh data; only layout and presentation changed.

Risk uses this structured layout:

- Top row: Risk Summary on the left and Queue Summary on the right.
- Primary center: Active Risk Findings as the main investigation panel.
- Supporting row: Top Risk Signals on the left and Recent Remediation Feed on the right.
- Bottom row: a wide Risk Timeline panel.
- Footer/detail row: Allowlist Status and Safety Boundary.

Wide terminals use side-by-side sections. Long values are sanitized and truncated to avoid horizontal scrolling. This layout pattern is intended to inform future 170.5B-G tab work.

Phase 170.5A.2 is display-only. It adds no runtime behavior changes, collectors, packet capture, enforcement, blocking, remediation execution, file writes, private data persistence, or firewall/process/service changes.

## Phase 170.5A.3 Risk Investigation Workspace

Phase 170.5A.3 converts Risk from a summary workspace into an investigation workspace. Risk Summary and Queue Summary stay in the top row, Active Risk Findings becomes the large primary center panel, and Timeline plus Remediation Feed remain supporting panels for context.

Active Risk Findings uses only the same existing runtime data already shown by Dashboard and Risk: sampled port rows and remediation preview events. It does not add collectors, scanners, packet capture, enforcement, filesystem writes, network activity, new runtime actions, or private data persistence.

Dashboard remains the operational overview screen with compact Risk Overview only.

## Phase 170.5A.4 Risk Dashboard Styling Parity

Phase 170.5A.4 restyles Risk to visually match Dashboard. Risk keeps the same investigation responsibilities and existing runtime data, but uses Dashboard-style section headers, dense unbordered content sections, compact table-like rows, and less empty space instead of large bordered boxes.

This dense operator layout becomes the style template for future 170.5B-G tabs. Dashboard styling and Dashboard's compact Risk Overview remain unchanged.

Phase 170.5A.4 is presentation-only. It adds no runtime behavior changes, collectors, packet capture, enforcement, blocking, remediation execution, file writes, private data persistence, or firewall/process/service changes.

## Phase 170.5A.5 Risk One-Screen Dashboard Layout

Phase 170.5A.5 changes Risk from a scroll-heavy investigation report into a one-screen dashboard layout for normal Mac and Raspberry Pi terminal sizes. It keeps Dashboard as shortcut `1` and the default operational overview, while Risk remains shortcut `2` for compact risk investigation.

The Risk screen now uses this visible structure:

- Top row: compact Risk Summary plus Queue Summary.
- Main table: Active Risk Findings with `Time`, `Source`, `Node`, `Port/Target`, `Score`, `State`, and `Signal` columns, capped at 6 rows.
- Supporting row: Top Risk Signals capped at 5 rows plus Recent Remediation Feed capped at 5 rows.
- Bottom table: Risk Timeline capped at 3 rows.
- Footer note: Allowlist/Safety in 2-3 lines total.

The default Risk tab should remain compact. Full historical or detail-heavy views can be added later as separate operator surfaces if needed, but the default Risk tab should not become a vertical report.

Phase 170.5A.5 is display-only. It adds no runtime behavior changes, collectors, packet capture, enforcement, blocking, remediation execution, file writes, private data persistence, or firewall/process/service changes.

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
