# Phase 141-146 Visual Intelligence Layer Plan

Milestone X turns PortMap-AI's telemetry, flow reconstruction, topology intelligence, policy evaluation, and advisory remediation foundations into operator-facing visual intelligence models. The focus is graph, timeline, asset, risk, fleet, and visual summary records that can support a future GUI/dashboard experience without adding a browser application or live enforcement in this milestone.

This is a planning document only. It does not add browser UI, modify firewall rules, inspect packet payloads, store raw packets, retain raw DNS history, execute remediation, isolate nodes, start services, contact external services, or perform destructive automation.

## Milestone X: Visual Intelligence Layer

Goal:
Turn PortMap-AI's working telemetry, flow reconstruction, topology intelligence, policy evaluation, and advisory remediation layers into operator-facing visual intelligence models that can support a future GUI/dashboard experience without adding live enforcement or browser UI yet.

All work should remain:

- visualization-model only
- local-first
- source-mode preserving
- metadata-only
- export-safe
- bounded
- advisory-first
- dry-run safe
- Raspberry Pi/Linux ARM compatible
- macOS/Linux/Windows aware
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 141:

- Live/default worker socket snapshots feed Milestone V runtime bridge summaries.
- Reconstructed sessions, flow summaries, metadata correlations, process/service correlations, relationship edges, attribution candidates, drift records, trust-zone records, and dependency records are available as metadata-only summaries.
- Milestone W policy, remediation recommendation, provider readiness, risk escalation, incident candidate, safety guardrail, rollback simulation, and enforcement-mode summaries are preview-only and advisory-first.
- Runtime health, cross-platform validation, deployment readiness, historical intelligence, export bundles, dashboard/API-safe dictionaries, and TUI source-mode labeling are already available.

Milestone X should convert those records into visual model contracts. It should not implement a new browser UI unless existing dashboard models are safely extended, and it must not change host or network state.

## Phase 141 - Interactive Network Topology Visualization

Status: Complete Baseline

Goal:
Build bounded topology graph records that convert flow, topology, asset, trust-zone, and dependency intelligence into export-safe graph models.

Build:

- `core_engine/visualization/topology_models.py`
- `core_engine/visualization/topology_builder.py`
- `core_engine/visualization/asset_classifier.py`
- `core_engine/visualization/graph_export.py`
- `tests/test_topology_builder.py`
- `tests/test_asset_classifier.py`
- `tests/test_graph_export.py`
- `docs/interactive_topology_visualization.md`

Features:

- Topology graph records.
- Node and edge records.
- Asset classification summaries.
- Flow-to-graph conversion helpers.
- Trust-zone and dependency overlays.
- Relationship strength and confidence summaries.
- Source-mode preservation.
- Bounded graph size controls.
- JSON-safe export models.
- Mermaid-safe export models.
- Cytoscape-safe export models.

Acceptance:

- Graphs are deterministic from sanitized fixtures.
- Duplicate nodes and edges collapse by stable IDs.
- Graph size limits prevent unbounded growth.
- Export models contain no private identifiers.
- No packet payloads, PCAPs, raw DNS history, enforcement, or browser UI is introduced.

## Phase 142 - Historical Network Timeline

Status: Complete Baseline

Goal:
Build replay-safe historical timeline records for topology, flow, service, asset, drift, policy, and advisory-remediation changes.

Build:

- `core_engine/visualization/timeline_models.py`
- `core_engine/visualization/timeline_builder.py`
- `tests/test_historical_network_timeline.py`
- `docs/historical_network_timeline.md`

Features:

- Timeline event records.
- Topology change summaries.
- Flow change summaries.
- Service change summaries.
- Asset first-seen and last-seen events.
- Drift and attribution change events.
- Policy and recommendation review markers.
- Replay-safe visual summaries.
- Bounded event windows.
- Dashboard/API/export-safe timeline dictionaries.

Acceptance:

- Timeline windows remain bounded and deterministic.
- Missing historical inputs produce empty/degraded states.
- Replay-safe records do not re-run collectors.
- No raw packet, raw DNS, credential, screenshot, log, or private runtime artifact is stored.

## Phase 143 - Asset Inventory Intelligence

Status: Complete Baseline

Goal:
Build visual asset inventory intelligence records that summarize devices, services, inferred roles, observation windows, and confidence-scored labels.

Build:

- `core_engine/visualization/asset_inventory.py`
- `core_engine/visualization/asset_roles.py`
- `tests/test_asset_inventory_intelligence.py`
- `docs/asset_inventory_intelligence.md`

Features:

- Asset inventory records.
- Asset role inference helpers.
- First-seen and last-seen summaries.
- Observed service, flow, and timeline relationship counts.
- Confidence-scored asset labels.
- Source-mode rollups.
- Active, new, recurring, dormant, stale, and unknown asset states.
- Max-asset bounding and deduplication.
- Dashboard/API/export-safe inventory dictionaries.

Acceptance:

- Asset labels are confidence-scored and advisory.
- Unknown assets remain Unknown rather than receiving fake live labels.
- Fixture/simulated labels remain source-mode scoped.
- Inventory size is bounded and deterministic.
- No private hostnames, IPs, usernames, MACs, or hardware identifiers appear in public docs.

## Phase 144 - Risk Dashboard Models

Status: Complete Baseline

Goal:
Build risk dashboard model records that summarize policy, remediation, drift, attribution, topology, runtime, and provider-readiness context as operator-safe visual panels.

Build:

- `core_engine/visualization/risk_dashboard.py`
- `core_engine/visualization/risk_cards.py`
- `tests/test_risk_dashboard_models.py`
- `docs/risk_dashboard_models.md`

Features:

- Risk panel records.
- Explanation records.
- Recommendation summaries.
- Overall risk score and highest severity summaries.
- Drift risk cards.
- Attribution risk cards.
- Topology risk cards.
- Policy match cards.
- Asset inventory risk cards.
- Runtime health cards.
- Guardrail and rollback safety cards.
- Empty/degraded panel states.
- Max-card bounding and deduplication.
- Dashboard/API/export-safe risk dictionaries.

Acceptance:

- Risk cards are advisory and do not become threat verdicts.
- Recommendations remain preview-only.
- Missing or low-confidence inputs degrade safely.
- Cards remain bounded and deterministic.
- No enforcement, quarantine, rollback, firewall, process, or service action is executed.

## Phase 145 - Multi-Node Fleet Visibility

Status: Complete Baseline

Goal:
Build site, group, node health, collector status, version, and check-in visual models for distributed and edge deployments.

Build:

- `core_engine/visualization/fleet_views.py`
- `core_engine/visualization/node_cards.py`
- `tests/test_multi_node_fleet_visibility.py`
- `docs/multi_node_fleet_visibility.md`

Features:

- Site view records.
- Group view records.
- Node health cards.
- Collector status models.
- Version summaries.
- Check-in summaries.
- Telemetry freshness states.
- Max-node bounding and deduplication.
- Raspberry Pi/edge readiness rollups.
- Windows/macOS/Linux compatibility rollups.
- Degraded, stale, offline, and unknown node states.
- Dashboard/API/export-safe fleet dictionaries.

Acceptance:

- Fleet views use logical node classes and sanitized identifiers.
- Stale and offline states are explicit.
- Version and check-in summaries do not expose private hostnames or usernames.
- Fleet records remain bounded across repeated updates.
- No service installation, remote command execution, credential handling, or network control is introduced.

## Phase 146 - Visualization Operator Summary

Status: Planned

Goal:
Build a unified visual intelligence summary that combines topology graphs, historical timelines, asset inventory, risk dashboard models, and fleet visibility into dashboard/API/export-safe operator records.

Build:

- `core_engine/visualization/visual_summary.py`
- `core_engine/visualization/operator_views.py`
- `tests/test_visualization_operator_summary.py`
- `docs/visualization_operator_summary.md`

Features:

- Unified visual intelligence summary records.
- Graph rollups.
- Timeline rollups.
- Asset inventory rollups.
- Risk panel rollups.
- Fleet visibility rollups.
- Readiness checklist records.
- Degraded and empty-state models.
- Source-mode and privacy/safety summaries.
- Dashboard/API/export-safe visual intelligence dictionaries.

Acceptance:

- Empty inputs produce useful empty-state models.
- Degraded inputs produce operator-safe degraded summaries.
- Dashboard/API/export dictionaries preserve source mode.
- Graph and timeline growth remain bounded.
- No browser UI, enforcement, packet payload inspection, raw packet storage, raw DNS history, or private identifiers are introduced.

## Milestone X Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Run `python -m pytest`.
- Run `git diff --check`.
- Review staged diffs.
- Run a sensitive-data scan.
- Run an artifact/private-file check.
- Confirm `docs/real_device_validation.md` remains unstaged.
- Confirm `testfile.txt` remains unstaged if present.
- Confirm no logs, artifacts, screenshots, caches, runtime outputs, databases, private credentials, certificates, or keys are staged.
- Confirm docs contain no real hostnames, IP addresses, usernames, MAC addresses, SSH details, tokens, credentials, certificates, keys, or private paths.
- Confirm visualization records are model-only and do not start a browser UI.
- Confirm all records preserve source mode.
- Confirm graph and timeline models remain bounded.
- Confirm no live enforcement, firewall changes, service actions, packet payload inspection, raw packet storage, or raw DNS history is introduced.

## macOS Validation Checklist

- Generate graph models from sanitized flow and topology fixtures.
- Generate timeline summaries from sanitized snapshot/replay fixtures.
- Generate asset inventory labels without private identifiers.
- Generate risk dashboard cards from Milestone W advisory records.
- Generate fleet cards for local and fixture node summaries.
- Confirm package docs and tests include the new plan.
- Confirm no browser UI, privilege request, firewall change, service action, packet capture, or enforcement occurs.

## Raspberry Pi / Linux ARM Validation Checklist

- Pull only after the Mac push succeeds.
- Run focused visualization model tests if full-suite runtime constraints require it.
- Validate bounded graph and timeline generation with small fixtures.
- Validate fleet and node cards with Raspberry Pi/edge resource summaries.
- Confirm CPU and RAM remain stable for repeated model generation.
- Confirm no screenshots, logs, runtime outputs, databases, or private validation artifacts are staged.

## Linux Validation Checklist

- Validate Linux node and collector status summaries.
- Validate topology, timeline, asset, risk, and fleet models from sanitized fixtures.
- Confirm graph and timeline boundedness.
- Confirm export dictionaries remain deterministic and sanitized.

## Windows Compatibility Fixture Checklist

- Validate Windows-style node cards, version summaries, collector status records, and degraded platform states.
- Validate graph, timeline, asset, risk, and fleet dictionaries from fixtures only.
- Confirm no registry, service, firewall, credential, certificate, key, installer, or browser action is modeled as completed.

## Safety Notes

- Milestone X is not a browser dashboard implementation.
- Milestone X is not active response.
- Milestone X does not enable threat verdicts.
- Milestone X does not inspect or store packet payloads.
- Milestone X does not store raw DNS browsing history.
- Milestone X prepares visualization data contracts for future GUI/dashboard work.
