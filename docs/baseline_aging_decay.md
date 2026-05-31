# Baseline Aging and Decay

Phase 112 adds metadata-only baseline aging and decay helpers for historical behavior records. The helpers reduce confidence in stale behavior, fade inactive observations, summarize dormant service and destination records, and identify long-term baseline maturity without triggering enforcement.

This feature is local-first, advisory-only, dry-run safe, and bounded by explicit policy records. It does not store packet payloads, credentials, raw browsing history, raw logs, private runtime artifacts, or real identifiers in public output.

## Aging Policies

Aging policies define safe local thresholds:

- Inactive age threshold.
- Stale age threshold.
- Dormant age threshold.
- Mature observation threshold.
- Mature age threshold.
- Confidence decay rate.
- Minimum confidence floor.

Default profiles are available for general use, Raspberry Pi-friendly retention, and longer historical windows. Policy records are deterministic and include safety fields showing that no service, firewall, packet, or external action is performed.

## Decay Records

Decay records can be built from existing metadata summaries:

- Historical flow baseline entries.
- Service fingerprint profiles.
- DNS and destination behavior profiles.
- Historical snapshot context.

Each decay record includes:

- Source record type and source reference.
- First-seen and last-seen timestamps.
- Age in days.
- Original confidence.
- Decayed confidence.
- Inactive, stale, dormant, and mature flags.
- Operator-readable decay state.
- Export-safe digest references.

Malformed input is isolated as a structured record. Raw malformed content is not stored.

## Operator Outputs

Phase 112 outputs are ready for CLI, dashboard, API, and export usage:

- `baseline_aging_decay_summary`
- `baseline_decay_explanation`
- `baseline_aging_decay_dashboard`
- `baseline_aging_decay_api`
- `baseline_aging_decay_export_summary`

Recommendations remain advisory. No automatic blocking, firewall change, service change, packet modification, or external reputation lookup occurs.

## Validation

Use sanitized fixtures and deterministic timestamps:

- Validate confidence decay over time.
- Validate inactive behavior fading.
- Validate stale service fingerprint handling.
- Validate dormant destination and fingerprint handling.
- Validate baseline maturity scoring.
- Validate empty and malformed input handling.
- Validate deterministic serialization.
- Confirm public docs contain no real IP addresses, domains, usernames, hostnames, MAC addresses, logs, screenshots, databases, cache files, runtime outputs, or private validation notes.
