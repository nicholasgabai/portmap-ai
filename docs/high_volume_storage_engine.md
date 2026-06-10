# High-Volume Storage Engine

Phase 154 adds metadata-only storage readiness models for larger telemetry deployments. The implementation defines retention tier records, storage capacity summaries, utilization and pressure states, write/read readiness summaries, and compaction previews without adding a live database dependency or writing runtime data.

## Retention Tiers

Retention tiers are advisory capacity records. They describe how metadata could be organized later, but they do not create storage backends or mutate files.

Supported tier types:

- `hot`
- `warm`
- `cold`
- `archive_preview`
- `unknown`

Each tier records bounded record capacity, byte capacity, retention window, priority, compaction policy, export policy, source mode, advisory notes, and fixed safety flags. Supported compaction policies are `none`, `summarize`, `sample`, `rollup`, `drop_preview`, and `unknown`.

## Storage Readiness

Storage summaries combine retention tier capacity with optional Phase 153 telemetry bus queue summaries. The summary reports total record capacity, total byte capacity, estimated current records and bytes, utilization ratio, pressure state, write capacity preview, read capacity preview, compaction preview, and advisory recommendations.

Supported storage states:

- `ready`
- `degraded`
- `pressure`
- `over_capacity`
- `unavailable`
- `unknown`

Pressure is derived from bounded utilization. Normal utilization remains `ready`, elevated utilization degrades readiness, pressure and over-capacity states produce advisory recommendations, and missing tiers produce an unavailable readiness record.

## Compaction Previews

Compaction records are previews only. They can recommend summarization, sampling, rollups, or drop-preview review, but they never delete data, rewrite records, perform compaction, or write to disk.

## Phase 153 Integration

Storage summaries can consume telemetry bus summaries from Phase 153 to estimate current queue pressure, retry pressure, dropped-by-bound counts, and topic distribution. This gives later scaling phases a capacity view without introducing external brokers, live forwarding, or runtime queue persistence.

## Safety Boundary

Phase 154 remains:

- metadata-only
- source-mode preserving
- bounded by record and byte capacity
- export-safe
- preview-only and advisory-first
- free of live database dependencies
- free of filesystem writes, runtime data writes, deletion, and destructive compaction
- free of raw payload storage, credential storage, private identifier export, remediation, enforcement, firewall changes, process changes, and service changes

## Future Consumption

Phase 155 can use storage summaries for shard and partition planning. Phase 156 can use utilization and pressure records for resource optimization previews. Phase 157 can use hot/warm/cold/archive-preview tiers to select edge-safe worker modes. Phase 158 can use the same readiness model for relay storage previews without starting a live cloud relay.
