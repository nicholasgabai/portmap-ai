# PortMap-AI Roadmap

This roadmap summarizes the current direction after the Phase 58 baseline. `PORTMAP_AI_HANDOFF.md` remains the canonical implementation record, and `docs/PHASE_HISTORY.md` summarizes completed phase groups.

## Current Baseline

Phases 0-58 are implemented locally in the working tree and documented as complete baselines. A complete baseline means the foundational implementation is operational and tested, while future work may expand depth, integrations, and production hardening.

## Near-Term Work

- Follow the Phase 44-53 local infrastructure visibility plan in `docs/PHASE_44_53_PLAN.md`.
- Use the Phase 44-53 integration plan in `docs/PHASE_44_53_INTEGRATION_PLAN.md` to guide consolidation before adding new runtime behavior.
- Use the Phase 54-58 advanced diagnostics plan in `docs/PHASE_54_58_PLAN.md` for future fixture-based diagnostics, metadata parsing, plugin governance, relay simulation, and service template work.
- Use the Phase 54-58 integration plan in `docs/PHASE_54_58_INTEGRATION_PLAN.md` to connect diagnostics and service-template records into platform layers without adding new runtime behavior.
- Use the local event pipeline in `docs/event_pipeline.md` as the event-history foundation for future storage, dashboard, and correlation work.
- Use the local SQLite storage layer in `docs/local_storage.md` for durable events, snapshots, assets, services, topology relationships, and findings.
- Use the local runtime scheduler primitives in `docs/runtime_scheduler.md` for future recurring health, event, snapshot, and operator-review workflows.
- Use the local node coordination primitives in `docs/node_coordination.md` for node identity, capabilities, heartbeats, lifecycle state, and summaries.
- Use the local read-only API primitives in `docs/local_api.md` for future dashboard and operator tooling work.
- Use the local dashboard foundation in `docs/dashboard_foundation.md` for static HTML status-panel previews.
- Use topology and timeline view models in `docs/topology_timeline_views.md` for local dashboard and operator reporting layers.
- Use the local policy review engine in `docs/policy_review_engine.md` for advisory review records and operator state transitions.
- Use distributed visibility aggregation in `docs/distributed_visibility_aggregation.md` to merge authorized local node summaries while preserving source attribution and reported conflicts.
- Use behavior correlation baselines in `docs/behavior_correlation.md` to compare stored local telemetry windows and produce advisory delta findings.
- Use the bounded schema validation engine in `docs/schema_validation_engine.md` for local mock-service fixture checks and controlled mutation testing.
- Use the metadata-only stream parser in `docs/metadata_stream_parser.md` for bounded local fixture and file metadata summaries.
- Use the manifest-based plugin registry in `docs/plugin_registry.md` for governed local utility manifests, dry-run previews, and structured execution records.
- Use the diagnostic relay simulator in `docs/diagnostic_relay_simulator.md` for bounded local relay orchestration metadata and platform integration records.
- Use service lifecycle templates in `docs/service_installer_templates.md` for dry-run systemd and Windows service template generation.
- Keep real-device validation notes private unless scrubbed for public documentation.
- Collect external Windows runtime validation before marking Windows support verified.
- Refresh screenshots, terminal examples, and quick-start paths after real-device testing.
- Prepare GitHub publication materials and release notes.
- Keep Docker Compose as an optional advanced deployment path.

## Medium-Term Work

- Harden service-management packaging for long-running agents.
- Expand dashboard usability while preserving the terminal-first product direction.
- Add more operator-friendly import/export flows for telemetry and advisory packets.
- Improve enterprise workflow documentation around organizations, roles, quotas, and sync manifests.

## Long-Term Vision

PortMap-AI aims to become an AI-native network observability, exposure management, telemetry intelligence, and remediation orchestration platform supporting local, distributed, and enterprise-scale deployments.

## References

- `PORTMAP_AI_HANDOFF.md`
- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md`
- `docs/behavior_correlation.md`
- `docs/dashboard_foundation.md`
- `docs/diagnostic_relay_simulator.md`
- `docs/distributed_visibility_aggregation.md`
- `docs/PHASE_44_53_INTEGRATION_PLAN.md`
- `docs/PHASE_44_53_PLAN.md`
- `docs/PHASE_54_58_INTEGRATION_PLAN.md`
- `docs/PHASE_54_58_PLAN.md`
- `docs/event_pipeline.md`
- `docs/local_api.md`
- `docs/local_storage.md`
- `docs/metadata_stream_parser.md`
- `docs/node_coordination.md`
- `docs/policy_review_engine.md`
- `docs/plugin_registry.md`
- `docs/runtime_scheduler.md`
- `docs/schema_validation_engine.md`
- `docs/service_installer_templates.md`
- `docs/topology_timeline_views.md`
- `docs/master_roadmap.md`
- `docs/real_device_validation.md`
