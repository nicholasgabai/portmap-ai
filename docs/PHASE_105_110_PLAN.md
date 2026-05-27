# Phase 105-110 Behavioral Intelligence Foundation Plan

Milestone R defines the next implementation milestone for adding the first historical behavioral intelligence layer to PortMap-AI. The focus is learning normal metadata patterns over time from already-approved telemetry summaries so the platform can distinguish stable behavior, new behavior, timing shifts, rare services, DNS novelty, and baseline-aware risk adjustments.

This is a planning document only. It does not implement collectors, start services, open network listeners, modify firewall rules, call external reputation services, store packet payloads, store credentials, deanonymize users, transmit telemetry externally, or perform automatic enforcement.

## Milestone R: Behavioral Intelligence Foundation

Goal:
Add the first historical behavioral intelligence layer for PortMap-AI so the platform can begin learning normal network behavior over time instead of only showing current telemetry snapshots.

Milestone R should connect the live telemetry, gateway enrichment, topology, runtime health, storage, review, export, dashboard/API, federation-safe, and cross-platform compatibility records into local historical behavior summaries.

All work should remain:

- local-first
- advisory by default
- dry-run safe
- metadata-only
- privacy-preserving
- resource-conscious
- Raspberry Pi compatible
- macOS/Linux/Windows aware
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 105:

- Runtime sessions, profiles, recovery, health, and service-readiness previews.
- Local event, storage, topology, policy review, export, and dashboard provider primitives.
- Trusted federation, distributed node state, cluster health, and operator visibility summaries.
- Passive interface discovery, packet metadata windows, flow reconstruction, protocol metadata extraction, and live topology correlation.
- Flow enrichment, process/service attribution, DNS visibility, router log ingestion, SPAN/mirror-port readiness, and gateway mode validation.
- Cross-platform runtime detection, Windows compatibility, packet capture readiness, firewall readiness, filesystem/export safety, and unified validation summaries.

Milestone R should add behavior learning from sanitized metadata summaries without adding raw payload storage, external reputation lookups, automatic blocking, or identity deanonymization.

## Phase 105 - Historical Flow Baselines

Status: Complete Baseline

Goal:
Build rolling historical baseline records for flow, service, port, and protocol metadata so PortMap-AI can identify stable and new behavior over local time windows.

Build:

- `core_engine/telemetry/behavior_baselines.py`
- `core_engine/telemetry/baseline_windows.py`
- `tests/test_historical_flow_baselines.py`
- `docs/historical_flow_baselines.md`

Features:

- Rolling baseline records for flows, services, ports, and protocols.
- First-seen and last-seen window fields.
- Frequency counters by flow key, service hint, port, protocol, and endpoint scope.
- Stable, new, recurring, and insufficient-history behavior classification.
- Baseline confidence scoring.
- Resource budget summaries for retained baseline windows.
- Metadata governance fields.
- Dashboard/API-ready baseline dictionaries.

Acceptance:

- Baselines are deterministic for sanitized fixture input.
- No raw packet payloads or credentials are stored.
- Missing or malformed telemetry records are handled safely.
- Bounded window retention is explicit in summaries.
- Existing telemetry, topology, and gateway tests continue to pass.

## Phase 106 - Temporal Anomaly Windows

Goal:
Add short, medium, and long time-window anomaly summaries for volume, burst, service timing, and rare behavior hints.

Build:

- `core_engine/behavior/anomaly_windows.py`
- `core_engine/behavior/temporal_anomalies.py`
- `tests/test_temporal_anomaly_windows.py`
- `docs/temporal_anomaly_windows.md`

Features:

- Time-window anomaly records.
- Short, medium, and long window summaries.
- Burst detection for flow, packet, byte, DNS, and service observations.
- Rare service timing detection.
- Volume drift hints.
- Advisory anomaly labels.
- Window confidence scoring.
- Operator-readable explanations.
- Dashboard/API-ready anomaly dictionaries.

Acceptance:

- Anomaly windows are deterministic for sanitized fixtures.
- Labels remain advisory and do not trigger enforcement.
- Low-history and sparse-data states are reported clearly.
- Resource limits prevent unbounded window growth.
- No external reputation or enrichment service is called.

## Phase 107 - Service Behavior Fingerprints

Goal:
Learn recurring service behavior fingerprints from metadata-only port, protocol, process, and service attribution summaries.

Build:

- `core_engine/behavior/service_fingerprints.py`
- `core_engine/behavior/service_profiles.py`
- `tests/test_service_behavior_fingerprints.py`
- `docs/service_behavior_fingerprints.md`

Features:

- Recurring service fingerprint records.
- Port, protocol, process, and service-name combination summaries.
- Expected service behavior profiles.
- Unusual service state detection.
- Fingerprint confidence summaries.
- Unsupported-platform and permission-degraded attribution handling.
- Privacy-preserving process metadata references.
- Dashboard/API-ready service behavior dictionaries.

Acceptance:

- Service fingerprints are deterministic for sanitized fixtures.
- Process metadata remains minimized and does not expose command-line secrets.
- Unsupported platform and permission-denied records degrade safely.
- Unusual service states remain review recommendations only.
- No automatic firewall or remediation action is created.

## Phase 108 - DNS and Destination Behavior Learning

Goal:
Learn recurring DNS, resolver, and destination metadata patterns with safe redaction and no external reputation lookups.

Build:

- `core_engine/behavior/dns_behavior.py`
- `core_engine/behavior/destination_learning.py`
- `tests/test_dns_destination_behavior_learning.py`
- `docs/dns_destination_behavior_learning.md`

Features:

- Recurring DNS/domain summaries.
- Destination reputation placeholder hooks with no external calls.
- Domain frequency and novelty scoring.
- Resolver behavior summaries.
- DNS timing and error pattern summaries.
- Safe domain truncation and redaction support.
- Encrypted DNS limitation records.
- Dashboard/API-ready DNS behavior dictionaries.

Acceptance:

- DNS and destination behavior summaries are deterministic for sanitized fixtures.
- External reputation services are not called.
- Domain metadata can be truncated or redacted for public/export use.
- Unknown, encrypted, and insufficient-history states degrade safely.
- No credentials or packet payload contents are retained.

## Phase 109 - Adaptive Risk Weighting

Goal:
Add local baseline-aware scoring helpers that adjust advisory risk using confidence, novelty, frequency, and temporal anomaly context.

Build:

- `core_engine/behavior/adaptive_risk.py`
- `core_engine/behavior/risk_explanations.py`
- `tests/test_adaptive_risk_weighting.py`
- `docs/adaptive_risk_weighting.md`

Features:

- Local adaptive scoring helpers.
- Baseline-aware score adjustments.
- Confidence-aware risk weights.
- Novelty, recurrence, burst, and unusual service weighting.
- Explanation records for operator review.
- Finding and review queue integration hooks.
- Export-ready risk explanation summaries.
- Dashboard/API-ready adaptive risk dictionaries.

Acceptance:

- Risk adjustments are deterministic for sanitized fixtures.
- Scoring remains advisory and local-only.
- Explanation records include evidence references and confidence values.
- No automatic enforcement, blocking, firewall modification, or remediation execution is added.
- Low-confidence inputs reduce certainty instead of inflating severity.

## Phase 110 - Behavioral Intelligence Operator Summary

Goal:
Summarize baselines, anomaly windows, service fingerprints, DNS behavior, and adaptive risk into operator-ready dashboard/API, review, and export records.

Build:

- `core_engine/behavior/operator_summary.py`
- `gui/web/behavior_views.py`
- `tests/test_behavioral_intelligence_operator_summary.py`
- `docs/behavioral_intelligence_operator_summary.md`

Features:

- Dashboard/API-ready behavior intelligence summaries.
- Export-ready baseline and anomaly summaries.
- Operator recommendations.
- Supported, degraded, unavailable, and insufficient-history state records.
- Baseline, anomaly, service fingerprint, DNS behavior, and adaptive risk rollups.
- Review-ready recommendation records.
- Resource and retention summaries.
- Federation-safe behavior summary dictionaries.

Acceptance:

- Operator summaries are deterministic for sanitized fixtures.
- Empty, degraded, and insufficient-history states render cleanly.
- Export records preserve redaction and placeholder requirements.
- No raw payload, credential, username, hostname, IP address, MAC address, private path, or runtime artifact is required in public outputs.
- Existing dashboard, TUI, telemetry, gateway, platform, and packaging tests continue to pass.

## Cross-Phase Data Flow

```text
metadata-only telemetry, DNS, service, topology, and gateway records
  -> historical flow baselines
  -> temporal anomaly windows
  -> service behavior fingerprints
  -> DNS and destination behavior learning
  -> adaptive risk weighting
  -> behavioral intelligence operator summaries
  -> review, export, dashboard/API, and federation-safe records
```

The flow learns local behavior from metadata summaries only. It does not retain payloads, identify users, call external services, block traffic, modify firewall rules, or execute remediation.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, local test files, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm all examples use sanitized placeholders only.
- Confirm no raw packet payloads, credentials, real IP addresses, MAC addresses, usernames, hostnames, tokens, private paths, or runtime artifacts are introduced.
- Confirm dry-run and advisory behavior remain the default.
- Confirm dashboard/API outputs are metadata-only and bounded.

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build flow baselines from sanitized reconstructed flows.
- Build anomaly windows across short, medium, and long fixture ranges.
- Build service fingerprints from sanitized attribution fixtures.
- Build DNS and destination behavior summaries with redaction enabled.
- Build adaptive risk explanations from baseline and anomaly records.
- Build behavioral operator summaries without starting services or collectors.
- Confirm no external reputation calls, payload storage, credential retention, blocking, firewall changes, or user deanonymization occurs.

## Raspberry Pi/Linux ARM Validation Checklist

Use sanitized records and small fixture sets only.

- Build bounded rolling baselines with Raspberry Pi resource budgets.
- Build anomaly windows with low record counts.
- Build service fingerprints with degraded attribution states where OS data is unavailable.
- Build DNS behavior summaries with truncation and encrypted DNS limitation records.
- Build adaptive risk summaries with conservative confidence scoring.
- Confirm CPU and memory use remain modest.
- Confirm no raw payloads, credentials, logs, screenshots, database files, cache files, runtime artifacts, or private validation notes are staged.

## Linux Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build flow, service, port, protocol, DNS, and destination baselines.
- Build anomaly windows and rare service timing hints.
- Build service behavior profiles from minimized process/service fixtures.
- Build dashboard/API-ready operator summaries.
- Confirm no firewall rules, packet capture modes, services, or runtime enforcement actions are modified.
- Confirm public docs and staged changes contain sanitized placeholders only.

## Windows Validation Checklist

Use sanitized fixtures and placeholder paths only.

- Build behavior summaries using Windows-compatible runtime profile and path records.
- Build process/service attribution degraded states without requiring elevation.
- Build DNS behavior summaries and redaction outputs.
- Build adaptive risk explanations without Windows Firewall changes or service control.
- Build dashboard/API-ready operator records.
- Confirm no registry writes, service installation, firewall modification, packet capture escalation, payload storage, or external reputation calls occur.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/historical_flow_baselines.md`
- `docs/temporal_anomaly_windows.md`
- `docs/service_behavior_fingerprints.md`
- `docs/dns_destination_behavior_learning.md`
- `docs/adaptive_risk_weighting.md`
- `docs/behavioral_intelligence_operator_summary.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Raw packet payload storage.
- Credential capture or storage.
- User deanonymization.
- External reputation service calls.
- Automatic blocking or enforcement.
- Firewall rule modification.
- Router or switch configuration changes.
- Service installation or startup.
- Hidden monitoring.
- Cloud sync or external telemetry transmission.
- Public docs containing real IP addresses, MAC addresses, hostnames, usernames, tokens, private paths, runtime logs, screenshots, databases, cache files, archives, or private validation notes.
