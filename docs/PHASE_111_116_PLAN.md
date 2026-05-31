# Phase 111-116 Historical Persistence and Long-Term Intelligence Plan

Milestone S defines the next implementation milestone for adding lightweight historical persistence and long-term behavioral memory to PortMap-AI. The focus is retaining, aging, summarizing, and replaying metadata-only behavioral intelligence over time without storing raw packet payloads.

This is a planning document only. It does not implement collectors, start services, create background persistence jobs, store packet payloads, store credentials, call external systems, modify firewall rules, or perform automatic enforcement.

## Milestone S: Historical Persistence and Long-Term Intelligence

Goal:
Add lightweight, resource-conscious historical persistence and long-term behavioral memory so PortMap-AI can retain, age, summarize, and replay behavioral intelligence over time without storing raw packet payloads.

Milestone S should connect Milestone R behavioral intelligence summaries to local storage, export, dashboard/API, gateway readiness, and cross-platform compatibility records through bounded metadata-only historical records.

All work should remain:

- local-first
- metadata-only
- privacy-preserving
- bounded by retention controls
- resource-aware
- Raspberry Pi compatible
- cross-platform aware
- advisory-only
- dry-run safe
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 111:

- Live telemetry metadata ingestion, flow reconstruction, protocol metadata, and dynamic topology correlation.
- Flow enrichment, process/service attribution, DNS visibility, gateway log ingestion, SPAN readiness, and gateway validation.
- Cross-platform runtime, capture, firewall, filesystem, export, and validation summaries.
- Historical flow baselines, temporal anomaly windows, service behavior fingerprints, DNS/destination behavior learning, adaptive risk weighting, and behavioral intelligence operator summaries.
- Local storage repositories, runtime export helpers, dashboard/API-ready records, and operational export bundles.

Milestone S should persist and replay metadata summaries only. It should not persist raw packet payloads, credentials, full browsing history, runtime logs, screenshots, private validation notes, or local artifacts.

## Phase 111 - Historical Snapshot Persistence

Status: Complete Baseline

Goal:
Add rolling metadata snapshot persistence records for behavioral intelligence outputs with rotation, retention windows, and export-safe summaries.

Build:

- `core_engine/history/snapshots.py`
- `core_engine/history/snapshot_store.py`
- `core_engine/history/__init__.py`
- `tests/test_historical_snapshot_persistence.py`
- `docs/historical_snapshot_persistence.md`

Features:

- Rolling metadata snapshot persistence records.
- Lightweight storage-ready snapshot dictionaries.
- Snapshot rotation helpers.
- Bounded retention windows.
- Snapshot source references.
- Snapshot summary counts.
- Export-safe persistence summaries.
- Dashboard/API-ready persistence dictionaries.

Acceptance:

- Snapshots are deterministic for sanitized behavioral summaries.
- Rotation and retention are bounded and explicit.
- Export summaries contain digests and record counts.
- No raw packet payloads, credentials, logs, screenshots, or private paths are stored.
- Tests use temporary paths and sanitized fixtures only.

## Phase 112 - Baseline Aging and Decay

Status: Complete Baseline

Goal:
Add aging and decay helpers for long-lived behavior baselines, inactive behavior, stale fingerprints, and confidence values.

Build:

- `core_engine/history/baseline_decay.py`
- `core_engine/history/aging_policies.py`
- `tests/test_baseline_aging_decay.py`
- `docs/baseline_aging_decay.md`

Features:

- Aging and decay records.
- Inactive behavior fading.
- Stale fingerprint handling.
- Confidence decay.
- Long-term baseline maturity tracking.
- Dormant behavior summaries.
- Operator-readable decay explanations.
- Dashboard/API-ready aging dictionaries.

Acceptance:

- Aging and decay are deterministic for sanitized fixtures.
- Mature baseline state is preserved without unbounded growth.
- Stale records degrade confidence instead of triggering enforcement.
- No external learning, reputation lookup, or automatic remediation is added.
- Tests cover inactive, stale, mature, and malformed inputs.

## Phase 113 - Long-Term Topology Evolution

Status: Complete Baseline

Goal:
Summarize how topology relationships evolve over time using stored metadata snapshots and bounded history.

Build:

- `core_engine/history/topology_evolution.py`
- `core_engine/history/relationship_history.py`
- `tests/test_long_term_topology_evolution.py`
- `docs/long_term_topology_evolution.md`

Features:

- Topology evolution summaries.
- Recurring node relationship tracking.
- Topology drift history.
- Stable versus transient relationship modeling.
- Relationship confidence tracking.
- Temporal edge summaries.
- Gateway and federation-aware topology history hooks.
- Dashboard/API-ready topology evolution dictionaries.

Acceptance:

- Topology evolution is deterministic for sanitized snapshots.
- Stable and transient relationships are classified clearly.
- History growth is bounded by retention settings.
- No active probing, bridge mode, packet injection, or router changes are added.
- Output remains local-only and advisory.

## Phase 114 - Historical Replay Windows

Status: Complete Baseline

Goal:
Add replay-safe behavioral summaries and bounded offline review helpers for historical timeline reconstruction.

Build:

- `core_engine/history/timeline_replay.py`
- `core_engine/history/replay_windows.py`
- `tests/test_historical_replay_windows.py`
- `docs/historical_replay_windows.md`

Features:

- Replay-safe behavioral summary windows.
- Historical timeline reconstruction records.
- Anomaly replay summaries.
- Bounded offline review helpers.
- Replay cursor and window metadata.
- Duplicate and stale replay protection.
- Export-ready replay summaries.
- Dashboard/API-ready replay dictionaries.

Acceptance:

- Replay windows are deterministic and bounded.
- Replay summaries do not re-run collectors or enforcement.
- Duplicate, stale, and malformed historical records are reported safely.
- Offline review helpers use sanitized fixture records only.
- No raw packet payloads or credentials are required.

## Phase 115 - Resource-Aware Historical Retention

Status: Complete Baseline

Goal:
Add Raspberry Pi-conscious and cross-platform retention controls for long-term metadata history.

Build:

- `core_engine/history/retention_policies.py`
- `core_engine/history/resource_retention.py`
- `tests/test_resource_aware_historical_retention.py`
- `docs/resource_aware_historical_retention.md`

Features:

- Raspberry Pi resource-aware retention controls.
- Adaptive retention windows.
- Storage safety summaries.
- Low-resource degradation states.
- Cross-platform path and export safety hooks.
- Retention recommendation records.
- Dry-run retention preview records.
- Dashboard/API-ready retention dictionaries.

Acceptance:

- Retention previews are deterministic for sanitized fixtures.
- Low-resource states degrade retention safely.
- No files are deleted or moved automatically.
- Tests write only to temporary directories.
- Public docs use placeholders only.

## Phase 116 - Long-Term Intelligence Operator Summary

Status: Complete Baseline

Goal:
Combine historical persistence, aging, topology evolution, replay, and retention summaries into operator-ready historical intelligence records.

Build:

- `core_engine/history/intelligence_summary.py`
- `core_engine/history/operator_views.py`
- `tests/test_long_term_intelligence_operator_summary.py`
- `docs/long_term_intelligence_operator_summary.md`

Features:

- Unified historical intelligence summaries.
- Export-ready persistence rollups.
- Dashboard/API historical intelligence views.
- Operator recommendations.
- Supported, degraded, and unavailable states.
- Retention and storage safety rollups.
- Replay and topology evolution rollups.
- Privacy/safety field summaries.

Acceptance:

- Operator summaries are deterministic for sanitized fixtures.
- Empty, degraded, and low-resource states render cleanly.
- Export records preserve redaction, digest, and placeholder requirements.
- Existing dashboard, TUI, telemetry, gateway, platform, behavior, and packaging tests continue to pass.
- No automatic enforcement, firewall changes, service changes, external calls, payload storage, or credential storage is added.

## Cross-Phase Data Flow

```text
behavioral intelligence summaries
  -> historical metadata snapshots
  -> baseline aging and decay
  -> long-term topology evolution
  -> historical replay windows
  -> resource-aware retention controls
  -> long-term intelligence operator summaries
  -> dashboard/API views and export bundles
```

The flow stores and replays metadata summaries only. It does not store packet payloads, credentials, browsing history verbatim, runtime logs, screenshots, databases, cache files, private validation notes, or local artifacts.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, local test files, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm all public examples use sanitized placeholders only.
- Confirm retention and replay operations are bounded and dry-run safe by default.
- Confirm no raw packet payloads, credentials, real IP addresses, MAC addresses, usernames, hostnames, tokens, private paths, or runtime artifacts are introduced.

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build rolling metadata snapshots from behavioral intelligence summaries.
- Apply aging and decay to historical baseline fixtures.
- Build topology evolution from sanitized relationship history.
- Build replay windows for offline review.
- Preview retention settings without deleting files.
- Build historical intelligence dashboard/API summaries.
- Confirm no external calls, payload storage, credential retention, firewall changes, or service changes occur.

## Raspberry Pi/Linux ARM Validation Checklist

Use small sanitized fixture sets only.

- Build bounded historical snapshots with low record counts.
- Apply conservative aging and decay settings.
- Build topology evolution with limited nodes and edges.
- Run replay windows over small metadata sets.
- Preview retention with Raspberry Pi resource thresholds.
- Confirm CPU, memory, and storage estimates remain modest.
- Confirm no logs, screenshots, database files, cache files, runtime artifacts, or private validation notes are staged.

## Linux Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build historical snapshots and export summaries.
- Apply baseline aging and stale fingerprint decay.
- Build topology drift history and stable/transient relationship summaries.
- Build replay-safe anomaly timelines.
- Preview retention controls without changing firewall, service, or capture state.
- Confirm dashboard/API summaries remain metadata-only.

## Windows Compatibility Fixture Checklist

Use placeholder paths and sanitized fixture records only.

- Build historical snapshots using Windows-compatible path summaries.
- Apply aging and decay without platform-specific filesystem assumptions.
- Build replay windows and export dictionaries.
- Preview retention without deleting files or writing registry keys.
- Confirm no Windows service control, firewall changes, elevation requests, packet capture escalation, or private identifiers are introduced.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/historical_snapshot_persistence.md`
- `docs/baseline_aging_decay.md`
- `docs/long_term_topology_evolution.md`
- `docs/historical_replay_windows.md`
- `docs/resource_aware_historical_retention.md`
- `docs/long_term_intelligence_operator_summary.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Raw packet payload storage.
- Credential storage.
- Browsing history stored verbatim.
- Automatic enforcement.
- Firewall rule modification.
- External reputation or telemetry services.
- Service installation or startup.
- Hidden monitoring.
- Unbounded retention.
- Public docs containing real IP addresses, MAC addresses, hostnames, usernames, tokens, private paths, runtime logs, screenshots, databases, cache files, archives, or private validation notes.
