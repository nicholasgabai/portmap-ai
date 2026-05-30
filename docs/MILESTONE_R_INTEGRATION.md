# Milestone R Integration

Milestone R adds the first historical behavioral intelligence layer for PortMap-AI. It turns current live telemetry and enrichment summaries into local behavior baselines, anomaly windows, service behavior profiles, DNS and destination learning, adaptive advisory scores, and unified operator summaries.

This milestone remains local-first, advisory-only, dry-run safe, metadata-only, privacy-preserving, and suitable for sanitized fixtures. It does not store raw packet payloads, credentials, raw browsing history, real private identifiers, or runtime artifacts. It does not call external reputation services, modify firewall rules, block traffic, alter services, or execute remediation.

## Phase Summary

### Phase 105 - Historical Flow Baselines

Historical flow baselines add rolling metadata-only baseline records for ports, protocols, services, process/service fingerprints, flow tuple digests, and DNS/domain observations. Baselines track first-seen and last-seen windows, frequency counters, rolling average scores, stable/new/recurring/decaying classifications, confidence scores, bounded retention, dashboard/API summaries, and export-ready digests.

### Phase 106 - Temporal Anomaly Windows

Temporal anomaly windows compare short, medium, and long behavior windows against local baselines. They report burst detection, rare service timing, volume drift hints, port/protocol/service novelty, baseline-aware advisory labels, confidence scoring, operator explanations, dashboard/API dictionaries, and export-ready summaries.

### Phase 107 - Service Behavior Fingerprints

Service behavior fingerprints learn recurring metadata-only process, service, protocol, port, transport, flow role, redacted DNS-summary, runtime platform, interface class, and direction combinations. They classify expected profiles, unusual process-port pairs, uncommon protocol bindings, dormant service returns, low-confidence profiles, dashboard/API summaries, and export-ready digests.

### Phase 108 - DNS and Destination Behavior Learning

DNS and destination behavior learning tracks recurring redacted or hashed domain summaries, resolver hashes, destination classification placeholders, frequency, recurrence timing, novelty, confidence, stable/new/recurring/unusual/dormant/drift labels, safe truncation and hashing controls, dashboard/API dictionaries, and export-ready digests.

### Phase 109 - Adaptive Risk Weighting

Adaptive risk weighting adjusts advisory scores using local baseline, anomaly, service fingerprint, and DNS/destination context. It supports stable behavior reductions, novelty and anomaly increases, unusual service and destination weighting, low-confidence dampening, score clamping, no-enforcement explanations, dashboard/API dictionaries, and export-ready digests.

### Phase 110 - Behavioral Intelligence Operator Summary

Behavioral intelligence operator summaries combine the Milestone R outputs into component rollups, supported/degraded/unavailable state summaries, advisory recommendations, explanation records, privacy/safety summaries, dashboard/API-safe operator views, and export-ready digests.

## Integration Points

### Live Telemetry

Milestone R consumes metadata-only packet, flow, protocol, and topology summaries produced by the live telemetry pipeline. It does not start collectors or capture loops by itself.

### Flow Enrichment

Flow enrichment provides packet/byte counters, first-seen and last-seen fields, endpoint scope, direction, service-port hints, state transitions, and confidence signals that feed baseline and anomaly records.

### Process And Service Attribution

Process and service attribution provides minimized socket ownership and service-name hints for service behavior fingerprints. Permission-denied and unsupported-platform states remain degraded metadata, not errors that trigger elevation.

### DNS Visibility

DNS visibility provides safe query/response metadata, domain-to-flow correlation, resolver classification, timing summaries, error summaries, encrypted DNS limitation records, and redaction controls for DNS and destination behavior learning.

### Runtime Exports

Baseline, anomaly, fingerprint, DNS behavior, adaptive risk, and unified behavior summaries each expose deterministic export-ready dictionaries and digests for local operator-controlled evidence bundles.

### Dashboard/API Views

Milestone R exposes dashboard/API-safe records for each behavioral component and a unified behavioral intelligence operator panel. The Textual TUI remains the primary operator UI; web dashboard models remain read-only summaries.

### Gateway Readiness

Gateway validation can consume behavioral intelligence summaries as advisory context for readiness state. Milestone R does not enable inline gateway enforcement, bridge mode, router changes, or automatic blocking.

### Cross-Platform Compatibility

Milestone R uses pure metadata records and deterministic fixture inputs, so behavior summaries run consistently across macOS, Linux, Raspberry Pi/Linux ARM, and Windows compatibility fixtures.

## Data Flow

```text
live telemetry and enrichment metadata
  -> historical flow baselines
  -> temporal anomaly windows
  -> service behavior fingerprints
  -> DNS and destination behavior learning
  -> adaptive risk weighting
  -> behavioral intelligence operator summaries
  -> dashboard/API views and export bundles
```

## macOS Validation Checklist

- Run the full test suite in the repo-local environment.
- Build sanitized baseline, anomaly, fingerprint, DNS/destination, adaptive risk, and unified behavior summary records.
- Confirm dashboard/API outputs contain metadata-only summaries.
- Confirm no external reputation calls, firewall changes, service changes, packet modifications, credentials, payloads, logs, screenshots, or private identifiers are introduced.

## Raspberry Pi/Linux ARM Validation Checklist

- Run focused behavioral intelligence tests with small sanitized fixture sets.
- Confirm bounded baseline and anomaly windows remain lightweight.
- Confirm service fingerprint and DNS behavior summaries work with degraded attribution inputs.
- Confirm adaptive risk output remains conservative and advisory-only.
- Confirm no raw payloads, credentials, databases, cache files, logs, screenshots, runtime artifacts, or private validation notes are staged.

## Linux Validation Checklist

- Build baselines from sanitized flow, service, port, protocol, and DNS records.
- Build temporal anomaly, service fingerprint, DNS/destination, adaptive risk, and operator summary records.
- Confirm gateway readiness consumes behavior summaries as advisory context only.
- Confirm no firewall rules, packet capture modes, services, or runtime enforcement actions are changed.

## Windows Compatibility Fixture Checklist

- Build behavioral summaries from Windows-compatible path and runtime fixture records.
- Confirm process/service attribution fallback records remain degraded rather than requiring elevation.
- Confirm DNS/destination summaries and adaptive risk explanations serialize safely.
- Confirm no Windows service control, registry writes, Windows Firewall changes, Npcap assumptions, packet capture escalation, or private identifiers are introduced.

## Safety Boundary

Milestone R is a behavioral intelligence summary layer. It does not perform enforcement. Any future action path must remain separate, explicit, operator-reviewed, and covered by separate safety tests.
