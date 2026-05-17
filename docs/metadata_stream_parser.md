# Metadata-Only Local Stream Parser

Phase 55 adds a local byte-stream metadata parser for PortMap-AI. The parser consumes sanitized in-memory fixtures or explicitly provided local files and extracts structural metadata for operator review and tests.

The refreshed baseline normalizes parser output into structured operational records for the event pipeline, storage layer, policy engine, topology/timeline systems, and correlation framework. These records are passive dictionaries; this phase does not publish, persist, review, correlate, or render them automatically.

This phase does not capture live interfaces, transmit data, inject packets, scan targets, install services, or perform automatic actions.

## Inputs

Supported local inputs:

- Bytes-like fixture data.
- Explicitly provided local files.

Supported frame modes:

- Whole input as one frame.
- Fixed-size frames.
- Delimiter-separated frames.
- Length-prefixed frames using 1, 2, or 4 byte big-endian prefixes.

All parsing is bounded by maximum input size and maximum frame count.

## Metadata Output

`parse_stream_bytes()` and `parse_stream_file()` return JSON-serializable metadata:

- `diagnostic_type`
- `record_version`
- `frame_count`
- `length_summary`
- `entropy_summary`
- `printable_ratio_summary`
- `hex_summary` per frame
- `detected_markers`
- `summary`
- `integration_hooks`
- `errors`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

Example:

```python
from core_engine.streams import parse_stream_bytes

result = parse_stream_bytes(
    b"HELLO|SAMPLE",
    delimiter=b"|",
    patterns=[
        {"name": "sample-text-marker", "type": "string", "value": "HELLO"},
        {"name": "sample-hex-marker", "type": "hex", "value": "53414d504c45"},
    ],
)
```

The parser summarizes frame bytes with bounded hex summaries. It does not store raw payload bytes by default.

## Operational Records

Phase 55 provides helper functions for converting parser results into platform-compatible records:

- `summarize_stream_result()`
- `build_stream_event()`
- `build_stream_finding()`
- `build_stream_timeline_entry()`
- `build_stream_storage_record()`
- `build_stream_topology_summary()`
- `build_stream_correlation_record()`

Example:

```python
from core_engine.streams import (
    build_stream_event,
    build_stream_storage_record,
    parse_stream_bytes,
)

result = parse_stream_bytes(b"HELLO|SAMPLE", delimiter=b"|")
event = build_stream_event(result)
storage_record = build_stream_storage_record(result)
```

Operational records are designed for later explicit integration:

- Event pipeline: `build_stream_event()`
- Storage layer: `build_stream_storage_record()`
- Policy engine: `build_stream_finding()`
- Timeline systems: `build_stream_timeline_entry()`
- Topology systems: `build_stream_topology_summary()`
- Correlation framework: `build_stream_correlation_record()`

All generated records preserve standard safety fields and avoid raw payload storage.

## Pattern Matching

Pattern helpers support:

- String pattern matching.
- Hex pattern matching.
- Pattern count limits.
- Pattern length limits.
- Case-insensitive string matching by default.

Invalid pattern definitions return structured unsupported results instead of crashing callers.

## Local File Parsing

`parse_stream_file()` reads an operator-provided local file path and returns metadata. The output includes only a file name, file size, and `path_stored: false`; it does not store the full local path.

## Status Values

Parser status values include:

- `ok`
- `malformed`
- `unsupported`
- `input_limited`

Malformed length-prefixed streams and oversized inputs return structured results with explanatory errors.

## Integration Hooks

Parser results include `integration_hooks`:

- `event_pipeline_ready`
- `storage_ready`
- `policy_review_ready`
- `timeline_ready`
- `topology_ready`
- `correlation_ready`

These booleans describe record compatibility only. They do not trigger runtime behavior.

## Safety Boundaries

- Local fixtures and explicit local files only.
- No live interface capture.
- No packet injection.
- No network transmission.
- No external export.
- No background scanning.
- No automatic enforcement.
- No raw payload persistence by default.

Use placeholders and sanitized examples only. Do not commit real IP addresses, MAC addresses, hostnames, usernames, tokens, secrets, screenshots, logs, local paths, runtime artifacts, or private validation notes.
