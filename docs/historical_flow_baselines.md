# Historical Flow Baselines

Phase 105 adds metadata-only rolling behavior baselines for flows, services, protocols, ports, process/service fingerprints, and DNS/domain observations.

The baseline layer is local-first, advisory, bounded, and privacy-preserving. It does not store packet payloads, credentials, packet captures, raw DNS payloads, or enforcement actions. It does not call remote learning or external reputation services.

## What Is Tracked

Baseline entries can be created for:

- ports
- protocols
- services
- process/service fingerprints
- flow tuple digests
- DNS/domain observations with safe sanitization

Each baseline entry includes:

- `first_seen`
- `last_seen`
- `observation_count`
- `rolling_frequency`
- `rolling_average_score`
- `stable_behavior`
- `novelty`
- `confidence`

Flow tuple baselines use digest-based keys instead of raw endpoint addresses. DNS/domain records use sanitized domain summaries and support redaction/truncation through existing DNS visibility helpers.

## Window Model

The baseline window helpers maintain three bounded windows:

- `short`
- `medium`
- `long`

Each window has a duration and maximum retained observation count. Window records include retained and dropped counts, category counts, key counts, first/last timestamps, and explicit safety fields.

The window model is intentionally lightweight:

- no raw packet storage
- no payload persistence
- no unbounded list growth
- no service startup
- no host configuration changes

## Behavior Classification

Baseline entries are classified as:

- `new`
- `recurring`
- `stable`
- `decaying_inactive`
- `insufficient_history`

Stable behavior requires repeated observations and enough recurrence across the configured windows. New behavior is advisory and review-ready only. Decaying inactive behavior is reported when a previous baseline is supplied but current metadata no longer contains the entry.

## Confidence Scoring

Confidence is deterministic and based on:

- observation frequency
- presence across multiple windows
- recurrence timing
- service or process/service stability
- rolling average metadata score

No ML model is trained or loaded. No remote learning service is contacted.

## Runtime And Operator Surfaces

The report builder emits:

- baseline entries
- window summaries
- dashboard-safe summaries
- API-safe dictionaries
- export-ready summary records with deterministic digests

The live telemetry operator summary includes a `behavior_baselines` panel when a baseline report is provided. Empty-state rendering remains clean when no behavior report is available.

## Safety Boundaries

Phase 105 does not:

- store payloads
- store credentials
- store full packet captures
- store raw DNS query contents beyond sanitized summaries
- create enforcement actions
- trigger firewall changes
- call external services
- deanonymize users
- require platform-specific privileged behavior

## Sanitized Example

```text
metadata-only flow observations
  -> bounded short/medium/long windows
  -> baseline entries for ports, protocols, services, flow tuples, DNS, and process/service fingerprints
  -> stable/new/recurring/decaying classifications
  -> dashboard/API/export-ready summaries
```

Use sanitized fixture addresses, node IDs, domains, and process labels only in public examples.
