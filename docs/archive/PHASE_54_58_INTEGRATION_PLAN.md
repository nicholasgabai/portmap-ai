# Phase 54-58 Integration Plan

This document consolidates the Phase 54-58 advanced diagnostics and deployment-readiness modules into a planned integration path. It is documentation planning only. It does not add runtime behavior, start services, execute plugins automatically, open relay listeners, install service units, transmit data externally, or modify host configuration.

The integration posture remains local-first, operator-controlled, deterministic, bounded, auditable, and suitable for lightweight Linux and Raspberry Pi deployments.

## Module Map

| Phase | Module | Role |
| --- | --- | --- |
| 54 | `core_engine.diagnostics.schema_validation` and `core_engine.diagnostics.fixture_mutation` | Validate structured inputs and generate deterministic bounded variants for diagnostic workflows. |
| 55 | `core_engine.streams.metadata_parser` and `core_engine.streams.patterns` | Parse operator-provided byte streams or local fixtures into metadata-only records. |
| 56 | `core_engine.plugins` | Validate plugin manifests, register allowlisted local utilities, and produce dry-run-first controlled execution records. |
| 57 | `core_engine.diagnostics.relay_simulator` | Simulate bounded local relay orchestration and produce session metadata records. |
| 58 | `core_engine.installers.service_templates` | Generate dry-run Linux and Windows service lifecycle template text for operator review. |

## Data Flow Diagram

Target flow for Milestone I records:

```text
operator-provided fixtures and definitions
  -> schema validation and mutation summaries
  -> metadata-only stream parsing
  -> governed plugin manifest and execution records
  -> bounded relay orchestration metadata
  -> dry-run service lifecycle templates
  -> event pipeline
  -> storage records
  -> topology and timeline views
  -> policy review queue
  -> behavior correlation
  -> local API and dashboard summaries
```

The flow is intentionally record-oriented. Each module produces structured output that can be consumed by existing platform layers without requiring active collection, external transport, automatic enforcement, or service installation.

## Implemented Modules

Phase 54 implemented:

- Schema definition validation.
- Fixture validation with bounded field, string, and byte limits.
- Deterministic fixture mutation.
- Validation result summaries.
- Event, finding, timeline, and correlation record builders.

Phase 55 implemented:

- Metadata-only byte stream parsing.
- Local file parsing with path suppression in public output.
- Frame length, entropy-style, printable-ratio, and marker summaries.
- Pattern normalization and matching.
- Event, finding, storage, topology, timeline, and correlation record builders.

Phase 56 implemented:

- Structured plugin manifest validation.
- Local plugin registry creation and allowlisted manifest registration.
- Dry-run-first plugin execution.
- Optional bounded local subprocess execution when explicitly requested.
- Timeout, environment allowlist, and output-size controls.
- Event, finding, storage, timeline, and correlation record builders.

Phase 57 implemented:

- Async bounded relay orchestration over mock local source and destination queues.
- Sequential forwarding metadata.
- Message, payload, byte, and duration bounds.
- Per-frame metadata without raw payload persistence.
- Event, finding, storage, topology, dashboard, timeline, and correlation record builders.

Phase 58 implemented:

- Systemd unit text generation.
- Windows service command/template text generation.
- Placeholder and operator-provided path validation.
- Dry-run deployment records.
- Dashboard, event, finding, storage, timeline, and correlation record builders.

## Connections To Platform Layers

### Event Pipeline

Each Phase 54-58 module can emit local event-shaped dictionaries:

- Schema validation: validation success, invalid fixture, malformed schema.
- Stream parsing: parsed metadata, malformed stream, input-limited stream.
- Plugin registry: manifest validation and controlled execution outcome.
- Relay orchestration: completed, limited, timed-out, or unsupported relay session.
- Service templates: valid template generation or invalid template request.

Target integration:

1. Module output is converted into an event record.
2. The event is serialized through the existing event serializer.
3. The event is published to the local event bus.
4. A future explicit flush step stores the event locally.

No module currently publishes automatically.

### Storage

Each module exposes storage-ready records or summary payloads. Target integration:

1. Operator-triggered diagnostics produce a result.
2. A storage adapter writes the module's storage record into the local SQLite findings or events repository.
3. Record payloads keep raw payload bytes out of storage.
4. Storage rows preserve safety fields:
   - `raw_payload_stored: false`
   - `automatic_changes: false`
   - `administrator_controlled: true`

### Policy Review

Non-successful classifications should become advisory review candidates:

- Schema validation: invalid or unsupported input.
- Stream parsing: malformed, unsupported, or input-limited input.
- Plugin execution: failed, timed-out, or unsupported execution.
- Relay orchestration: timed-out, unsupported, malformed, or input-limited sessions.
- Service templates: invalid or unsupported template requests.

Target integration:

1. Result builders produce finding records.
2. `core_engine.policy.evaluator` maps findings to enabled policies.
3. Review records are added to the local review queue.
4. Operators can approve, defer, dismiss, or resolve review records.

Approval remains a review-state change only. It does not execute plugins, install services, start services, change configuration, or contact external systems.

### Topology And Timeline

Timeline integration should use the event and timeline builders:

- Schema validation entries describe validation classifications.
- Stream parsing entries summarize frame and marker observations.
- Plugin entries summarize manifest or execution outcomes.
- Relay entries summarize session forwarding state.
- Service template entries summarize dry-run template generation.

Topology integration is available where relationships are meaningful:

- Stream parser marker summaries can become local stream-to-marker graph nodes.
- Relay orchestration can become mock source-to-destination relationships.
- Service templates can be attached to service-template references.

All graph and timeline output remains read-only.

### Correlation

Correlation records can feed the existing local baseline and behavior-correlation layers:

- Repeated schema validation failures can indicate recurring input drift.
- Repeated stream marker observations can support local metadata trend summaries.
- Repeated plugin execution failures can indicate local utility health issues.
- Relay timeout or input-limit records can indicate resource or bound tuning needs.
- Service template validation issues can indicate deployment-readiness gaps.

Correlation output remains advisory. It does not trigger collection, execution, installation, or enforcement.

### Dashboard And API

The dashboard/API path should consume summaries rather than raw payloads:

- Validation status counts.
- Stream frame counts and detected marker counts.
- Plugin registry count, lifecycle state counts, and execution status.
- Relay message counts, byte totals, and review status.
- Service template count, platform count, and dry-run status.

Target integration:

1. Records are persisted or provided by an in-memory provider.
2. Local read-only API endpoints expose summaries.
3. Dashboard models render status panels and counts.

Default runtime binding should remain localhost-only when an API service is explicitly started in a future phase.

## What Is Not Wired Together Yet

The following integrations are intentionally not active:

- Schema validation results automatically publishing to the event bus.
- Stream parser results automatically writing to storage.
- Plugin registry entries automatically executing through the scheduler.
- Relay orchestration running as a listener or background service.
- Service template output writing files or installing services.
- Policy review approvals triggering plugin execution or service actions.
- Dashboard/API loading Phase 54-58 records from SQLite by default.
- Correlation jobs consuming Phase 54-58 records automatically.

These should remain future explicit implementation tasks with focused tests.

## Raspberry Pi Validation Checklist

Use sanitized fixtures and placeholder service definitions only.

- Import all Phase 54-58 modules in the local virtual environment.
- Run the full Python test suite on the device.
- Validate a small schema against a sanitized fixture.
- Generate a bounded fixture mutation set.
- Parse a small local byte fixture and confirm metadata-only output.
- Validate a sample plugin manifest without executing it.
- Run a plugin dry-run preview and confirm no subprocess launches.
- Run a tiny controlled plugin execution only in a dedicated test fixture.
- Simulate a short relay session with mock payloads.
- Generate systemd and Windows service template text using placeholders.
- Confirm no service files are written by the template module.
- Confirm no service enable/start command is executed by PortMap-AI.
- Confirm no external network calls are required.
- Confirm CPU and memory use remain modest during focused tests.
- Confirm generated records keep `raw_payload_stored: false`.
- Confirm generated records keep `automatic_changes: false`.
- Confirm generated records keep `administrator_controlled: true`.
- Confirm no local validation notes, logs, screenshots, database files, cache folders, or environment files are staged.

## Recommended Next Phases

Suggested phases after Milestone I consolidation:

1. Phase 59 - Diagnostic record adapters.
   Add reusable adapters that convert Phase 54-58 results into event, storage, policy, timeline, topology, dashboard, and correlation records through a single local interface.

2. Phase 60 - Storage-backed diagnostics history.
   Persist selected diagnostic summaries locally and add query helpers for recent validation, stream, plugin, relay, and service-template records.

3. Phase 61 - Policy review wiring for diagnostics.
   Connect diagnostic findings to the local policy review queue without executing actions.

4. Phase 62 - Local API diagnostics endpoints.
   Add read-only API endpoints for diagnostic summaries, plugin registry status, relay summaries, and service-template previews.

5. Phase 63 - Dashboard diagnostic panels.
   Render local diagnostics panels using API-compatible summaries and no heavy frontend build system.

6. Phase 64 - Scheduler opt-in diagnostic maintenance.
   Add operator-enabled scheduler jobs for event flushing and summary refreshes only.

7. Phase 65 - Integrated Raspberry Pi diagnostics smoke path.
   Validate the local-only diagnostics path on lightweight Linux hardware using sanitized records.

## Safety Requirements

- Local-first behavior only.
- Operator-controlled workflows only.
- Advisory and read-only by default.
- No automatic plugin execution.
- No automatic service installation.
- No service enable/start execution.
- No router or firewall modification.
- No cloud sync or external transport.
- No live relay listener in this integration plan.
- No raw payload persistence.
- No real IP addresses, MAC addresses, hostnames, usernames, tokens, screenshots, local paths, logs, or private validation data in public docs, tests, or examples.
