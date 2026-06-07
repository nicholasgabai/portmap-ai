# Asset Inventory Intelligence

Phase 143 adds visualization-ready asset inventory intelligence models for PortMap-AI. Inventory records convert topology nodes, flow summaries, service hints, timeline activity, endpoint classes, and recurrence metadata into bounded asset summaries for future dashboard/API/export views.

This phase is model-only. It does not write inventory databases, start a GUI, start a browser UI, inspect packet payloads, store raw packets, retain raw DNS history, execute remediation, modify firewall/process/service state, or export private identifiers.

## Asset Role Inference

`core_engine.visualization.asset_roles` classifies assets into advisory roles:

- `workstation`
- `server`
- `router`
- `switch`
- `printer`
- `nas`
- `phone`
- `iot`
- `dns_resolver`
- `cloud_service`
- `external_service`
- `unknown`

Role inference uses metadata-only hints such as topology node class, endpoint class, observed services, common ports, flow direction, recurrence, and confidence signals. Unknown or low-confidence assets remain `unknown` rather than receiving fake live labels.

## Inventory Records

`core_engine.visualization.asset_inventory` defines `AssetInventoryRecord` entries with:

- sanitized `asset_id`
- advisory `asset_label`
- inferred `asset_role`
- `asset_state`
- bounded `confidence_score`
- `first_seen` and `last_seen`
- observed service and flow counts
- related node, flow, and timeline references
- preserved `source_modes`
- role evidence
- risk summary
- advisory notes

Supported asset states are `active`, `new`, `recurring`, `dormant`, `stale`, and `unknown`.

## First-Seen And Last-Seen

Inventory builders merge timestamps from topology nodes, related flows, service records, and timeline events. The earliest available timestamp becomes `first_seen`; the latest available timestamp becomes `last_seen`.

These fields are summaries only. They do not imply packet retention, DNS history retention, or a persistent asset database.

## Confidence Scoring

Asset confidence combines role confidence with available supporting metadata:

- sanitized node or asset references
- service hints
- flow references
- timeline references
- first-seen and last-seen summaries

Scores are deterministic and bounded between `0.0` and `1.0`. Conflicting, malformed, or missing metadata degrades confidence instead of inventing labels.

## Bounded Inventory Summaries

`build_asset_inventory` creates `AssetInventorySummary` records with:

- `asset_count`
- role counts
- state counts
- confidence min/max/average
- bounded asset rows
- `max_assets`
- export-safe safety flags

Repeated assets deduplicate by stable sanitized metadata. The `max_assets` limit prevents unbounded growth on Raspberry Pi, edge devices, long-running tests, exports, and future dashboard rendering.

## Privacy And Export Safety

Phase 143 exports sanitized metadata only. Inventory records preserve source mode values such as `live`, `fixture`, `simulated`, `replay`, and `unknown`, but they do not expose raw hostnames, private addresses, usernames, MAC addresses, hardware identifiers, credentials, certs, keys, raw packet payloads, raw DNS browsing history, screenshots, logs, runtime outputs, or local databases.

## Future Dashboard Path

The inventory model prepares a stable contract for future GUI/dashboard asset views. Later phases can render role counts, active/stale assets, first-seen and last-seen summaries, and confidence indicators without changing collectors or host/network state.

## Validation

Use sanitized fixtures only:

- Run `python -m pytest tests/test_asset_inventory_intelligence.py`.
- Run the full test suite before committing.
- Run `git diff --check`.
- Run a sensitive-data scan.
- Confirm `docs/real_device_validation.md`, local test files, logs, artifacts, screenshots, caches, runtime outputs, and databases remain unstaged.
