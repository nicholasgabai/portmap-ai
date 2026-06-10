# Distributed Telemetry Bus

Phase 153 adds metadata-only distributed telemetry bus models for local message envelopes, telemetry topics, bounded queues, fanout readiness, retry/backoff previews, and export-safe bus summaries.

The telemetry bus is a model layer only. It does not add an external broker, cloud service, network transport changes, live message forwarding, filesystem-backed queues, enforcement, remediation execution, firewall changes, process changes, service changes, credential storage, raw payload storage, or private identifier export.

## Envelope Model

Telemetry bus envelopes describe one local metadata message candidate. Each envelope includes:

- Topic and message type.
- Sanitized source node and target scope references.
- Source mode.
- Created timestamp.
- Priority.
- Retry count, max retries, and backoff seconds.
- Sanitized payload summary.
- Payload reference.
- Delivery state.
- Preview-only and non-destructive safety fields.

Supported topics are:

- `worker_telemetry`
- `flow_summary`
- `topology_update`
- `policy_evaluation`
- `remediation_preview`
- `visualization_summary`
- `intelligence_summary`
- `runtime_health`
- `audit_event`
- `unknown`

Supported delivery states are:

- `queued`
- `delivered_preview`
- `retry_pending`
- `dropped_by_bound`
- `invalid`
- `unknown`

Payload summaries describe shape, counts, field names, and digests. They do not store raw payload bodies or private identifiers.

## Bounded Queues

The bus summary builder normalizes envelope inputs into an in-memory queue summary. The queue is bounded by `max_queue_depth`.

If more envelopes are provided than the bound allows, the summary records the dropped count and adds a `dropped_by_bound` preview envelope. This preserves operator visibility into pressure without storing excess message payloads or writing queue files.

## Retry And Backoff Previews

Retry metadata is advisory only:

- `retry_count` records how many preview retries have been modeled.
- `max_retries` records the configured upper bound.
- `backoff_seconds` records the next preview delay.
- `retry_pending_count` summarizes queued or retry-pending envelopes.

No retry worker, network send, or background dispatcher is started.

## Fanout Readiness

Fanout readiness indicates whether the current bounded queue could be fanned out to known local target groups in a future implementation. It is a readiness flag only.

`external_broker_required` is always false in Phase 153. Future broker, relay, or SaaS behavior must be introduced by a later explicitly approved phase.

## Bus Summary

Telemetry bus summaries include:

- Queue depth and max queue depth.
- Dropped count.
- Retry pending count.
- Topic counts.
- Priority counts.
- Delivery state counts.
- Fanout readiness.
- Export-safe envelope dictionaries.
- Preview-only and non-destructive safety fields.

Bus states include `ready`, `degraded`, `empty`, `bounded`, `unavailable`, and `unknown`.

## Phase 154-158 Consumption Path

Later Milestone Z phases can consume bus summaries as metadata inputs:

- Phase 154 can use queue depth, topic counts, and dropped counts for storage planning and retention tiers.
- Phase 155 can use topic and queue pressure summaries for scaling and partition previews.
- Phase 156 can use retry, drop, and queue pressure data for adaptive sampling and load-shedding recommendations.
- Phase 157 can use source mode and queue summaries for edge worker and degraded/offline behavior models.
- Phase 158 can use fanout readiness and target scopes for relay readiness previews.

## Safety Boundary

Phase 153 remains:

- Metadata-only.
- Bounded.
- In-memory.
- Export-safe.
- Source-mode preserving.
- Cross-platform ready for Windows, macOS, Linux, and Raspberry Pi/Linux ARM.
- Free of external brokers.
- Free of network forwarding.
- Free of filesystem-backed runtime queues.
- Free of enforcement and remediation actions.
- Free of raw payload storage and private identifier export.
