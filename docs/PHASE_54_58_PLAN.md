# Phase 54-58 Advanced Diagnostics Plan

This document defines the next PortMap-AI planning phases after the Phase 44-53 local infrastructure visibility work. Phase 54 is now implemented as a local baseline; Phases 55-58 remain planning targets only. These phases do not add runtime behavior, background services, external transport, automatic collection, automatic enforcement, or service installation.

The shared posture remains local-first, operator-controlled, fixture-driven where possible, safe by default, and compatible with lightweight Linux and Raspberry Pi deployments.

## Milestone I: Advanced Local Diagnostics and Deployment Readiness

Milestone I prepares PortMap-AI for safer local diagnostics, metadata parsing, controlled utility plugins, loopback-only relay simulation, and documented service installation templates.

Core principles:

- Use sanitized examples only.
- Prefer test fixtures and operator-provided local files.
- Keep default behavior dry-run, advisory, or metadata-only.
- Avoid live interface capture in these phases unless a later phase explicitly adds it.
- Do not transmit data externally by default.
- Do not modify routers, firewalls, registry settings, services, or system configuration.
- Preserve existing CLI behavior.
- Preserve Raspberry Pi and general Linux compatibility.
- Add focused tests for every phase.

## Phase 54 - Bounded Schema Validation Engine

Status: complete baseline.

Goal:
Create a bounded schema validation and fixture mutation engine for local mock-service testing only.

Build:

- `core_engine/diagnostics/schema_validation.py`
- `core_engine/diagnostics/fixture_mutation.py`
- `tests/test_schema_validation.py`
- `docs/schema_validation_engine.md`

Features:

- Expected message or packet-like schema definitions.
- Bounded field validation for required fields, optional fields, types, lengths, and allowed values.
- Safe fixture mutation of field lengths, byte values, missing fields, and unexpected fields.
- Exception and result classification for valid, invalid, malformed, unsupported, and mutation-limited cases.
- JSON-serializable validation results with advisory explanations.
- Resource bounds for mutation count, fixture size, and generated variants.

Acceptance:

- Schemas can validate sanitized fixture dictionaries and byte-like fixture metadata.
- Mutation helpers produce bounded fixture variants without executing external programs.
- Malformed fixtures return structured errors instead of crashing callers.
- Tests use sanitized sample fixtures only.

Safety boundaries:

- Local mock-service testing only.
- No live targets.
- No network transmission.
- No router or firewall changes.
- No automatic remediation.
- No raw payload persistence by default.

## Phase 55 - Metadata-Only Local Stream Parser

Goal:
Add a metadata-only byte-stream parser that consumes local test fixtures or operator-provided local files and extracts structural metadata.

Build:

- `core_engine/streams/metadata_parser.py`
- `core_engine/streams/patterns.py`
- `tests/test_metadata_stream_parser.py`
- `docs/metadata_stream_parser.md`

Features:

- Parse byte frames from local fixtures or explicitly provided local files.
- Extract frame count, length summaries, entropy-like summaries, printable ratios, hex summaries, and detected markers.
- Support string and hex pattern matching through bounded, local pattern definitions.
- Return JSON-serializable metadata-only results.
- Apply input size limits and frame count limits.
- Report unsupported or oversized input through structured results.

Acceptance:

- Parser handles empty, short, malformed, and multi-frame fixture streams.
- Pattern matching works for sanitized string and hex examples.
- Output does not store raw payload bytes by default.
- Tests use temporary fixture files and in-memory sample bytes.

Safety boundaries:

- No live interface capture in this phase.
- No packet injection.
- No external data export.
- No background scanning.
- No automatic action.

## Phase 56 - Manifest-Based Plugin Registry

Goal:
Add a controlled internal plugin registry for local utility wrappers.

Build:

- `core_engine/plugins/manifest.py`
- `core_engine/plugins/registry.py`
- `core_engine/plugins/runner.py`
- `tests/test_plugin_registry.py`
- `docs/plugin_registry.md`

Features:

- Plugin manifest validation for name, version, description, command, permissions, and declared outputs.
- Allowlisted local plugin directories or explicit operator-provided paths.
- Safe subprocess wrapper for local utility execution.
- Timeout enforcement.
- Environment variable allowlist.
- Standard output and standard error size limits.
- Dry-run mode that reports intended execution without running commands.
- Structured result records for completed, timed-out, failed, skipped, and dry-run executions.

Acceptance:

- Valid manifests load and invalid manifests are rejected with clear errors.
- Registry only accepts allowlisted plugin locations.
- Runner enforces timeout, output limits, dry-run mode, and environment allowlist.
- Tests use local temporary plugin fixtures only.

Safety boundaries:

- Local utility wrappers only.
- No remote plugin fetching.
- No automatic plugin execution.
- No unbounded subprocess output.
- No unrestricted environment pass-through.
- No privilege escalation.

## Phase 57 - Diagnostic Relay Simulator

Goal:
Create a loopback-only relay simulator for local diagnostic testing and operator education.

Build:

- `core_engine/diagnostics/relay_simulator.py`
- `tests/test_relay_simulator.py`
- `docs/diagnostic_relay_simulator.md`

Features:

- Async loopback-only TCP relay simulator.
- Mock source and mock destination only.
- Sequential forwarding inside a local test harness.
- Metadata parsing for administrative review.
- Bounded connection, byte, and runtime limits.
- Structured run summaries for started, completed, timed-out, and rejected states.

Acceptance:

- Simulator refuses non-loopback bind or target values.
- Mock source and destination exchange sanitized fixture bytes locally.
- Metadata summaries are produced without storing raw payload bytes by default.
- Timeout and byte limits are enforced.
- Tests run without contacting external hosts.

Safety boundaries:

- Loopback-only.
- Test harness only.
- No open relay behavior.
- No external network transport.
- No service installation.
- No automatic background execution.

## Phase 58 - Documented Service Installer Templates

Goal:
Add documented service installer templates for Linux systemd and Windows service configuration, without installing services automatically.

Build:

- `core_engine/installers/service_templates.py`
- `docs/service_installer_templates.md`
- `tests/test_service_templates.py`

Features:

- Generate systemd unit text.
- Generate Windows service command or template text.
- Validate paths as placeholders or explicit operator-provided values.
- Dry-run output only.
- Include placeholders for user, working directory, executable path, environment file path, service name, and service description.
- Include warnings for privileged installation steps that must remain operator-controlled.

Acceptance:

- Template helpers generate deterministic sanitized output.
- Placeholder values validate cleanly.
- Unsafe or empty service names are rejected.
- Tests confirm no service enable, start, registry modification, or privilege escalation command is executed.

Safety boundaries:

- No automatic installation.
- No registry changes.
- No privilege escalation.
- No service enable/start execution.
- No local path examples in committed docs or tests.

## Cross-Phase Data Flow

Planned local-only flow:

```text
sanitized fixtures or operator-provided local files
  -> bounded schema validation
  -> metadata-only stream parsing
  -> optional dry-run plugin utility wrapper
  -> optional loopback-only relay simulation
  -> advisory diagnostic summaries
  -> documented service template output
```

No phase in this plan sends data externally, installs a service, captures live interfaces, modifies configuration, or executes automatic response workflows.

## Documentation Requirements

Each phase should include a dedicated public doc:

- `docs/schema_validation_engine.md`
- `docs/metadata_stream_parser.md`
- `docs/plugin_registry.md`
- `docs/diagnostic_relay_simulator.md`
- `docs/service_installer_templates.md`

Docs must use placeholders and sanitized examples only. Do not include real IP addresses, MAC addresses, hostnames, usernames, tokens, secrets, screenshots, logs, local paths, runtime artifacts, or private validation notes.

## Test Requirements

Each phase should add focused tests covering:

- Normal valid fixture behavior.
- Invalid and malformed input.
- Boundary limits.
- Dry-run or metadata-only behavior.
- Safety flags and structured result fields.
- Sanitized output checks.
- No automatic network, service, router, registry, firewall, or configuration changes.

## Do Not Build In Phases 54-58

- Hosted SaaS features.
- Cloud sync.
- Public internet exposure.
- Live packet capture.
- Packet injection.
- Automatic enforcement.
- Automatic service installation.
- Registry edits.
- Privilege escalation.
- Remote plugin fetching.
- Unbounded subprocess execution.
- Heavy ML training.
- Third-party data export.

## Raspberry Pi Compatibility Notes

The implementation should remain lightweight:

- Prefer standard-library modules where practical.
- Keep fixture sizes bounded.
- Keep parser and mutation loops bounded.
- Keep subprocess timeouts short and configurable.
- Avoid always-on behavior until a later explicit operator-enabled phase.
- Run tests with temporary files and in-memory fixtures.
- Confirm no generated logs, databases, archives, screenshots, cache files, environment files, or runtime artifacts are committed.

## Suggested Implementation Order

Recommended order:

1. Phase 54 schema validation and fixture mutation.
2. Phase 55 metadata-only stream parser.
3. Phase 56 manifest-based plugin registry.
4. Phase 57 loopback-only relay simulator.
5. Phase 58 service installer templates.

This order builds from safe local fixture validation toward controlled local execution wrappers and finally documented deployment readiness templates.
