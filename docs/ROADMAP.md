# PortMap-AI Roadmap

This roadmap summarizes the current direction after the Phase 58 baseline. `PORTMAP_AI_HANDOFF.md` remains the canonical implementation record, `docs/PHASE_HISTORY.md` records completed phase groups, and `docs/MILESTONE_INTEGRATION.md` is the active integration guide.

## Completed Milestones

| Range | Milestone | Status |
| --- | --- | --- |
| 0-18 | Local stack, CLI, packaging, configuration, platform abstraction, safety, deployment, and release-candidate foundation | Complete baseline |
| 19-40 | Scanner expansion, packet metadata, protocol intelligence, AI advisory layers, enterprise primitives, visualization, cluster planning, and local enterprise cloud scaffolding | Complete baseline |
| 41-43 | Local visibility tooling, sanitized example datasets, visibility snapshots, and baseline delta reporting | Complete baseline |
| 44-46 | Local intelligence platform: event model, storage, and scheduler primitives | Complete baseline |
| 47-48 | Coordinated node platform: node identity and local read-only API primitives | Complete baseline |
| 49-50 | Operator dashboard foundation: static dashboard rendering, topology graphs, and timelines | Complete baseline |
| 51-53 | Policy and correlation engine: review queue, distributed aggregation, and behavior correlation | Complete baseline |
| 54-58 | Advanced diagnostics and deployment readiness: schema validation, stream metadata, plugin governance, relay orchestration, and service templates | Complete baseline |

## Current Implementation State

Phases 0-58 are implemented locally in the working tree and documented as complete baselines. A complete baseline means the foundational implementation is operational and tested, while future work may expand integration depth, production hardening, and operator workflows.

Current stable posture:

- Local-first operation remains the default.
- Workflows remain opt-in and operator-controlled.
- Advisory behavior remains read-only by default.
- Runtime and diagnostic modules emit structured records but are not automatically wired together.
- The Textual terminal dashboard remains the primary operator UI.
- Static web dashboard rendering exists as a reusable foundation, not a replacement UI.
- Docker remains optional and advanced.
- Private real-device validation notes stay out of public commits unless scrubbed.

## Next Milestone Direction

Recommended next milestone: Milestone J - Runtime Pipeline and Persistent Topology Integration.

Near-term implementation should focus on wiring existing primitives together without adding unsafe automation:

- Use `docs/PHASE_59_64_PLAN.md` as the active implementation plan.
- Persist topology state and topology snapshot history.
- Compare baseline/current snapshots for asset, service, topology, and finding drift.
- Wire visibility, events, storage, policy review, topology, and correlation into one explicit operator workflow.
- Persist operator review drafts, approval states, finding status, and review history.
- Connect dashboard models to local API, storage, and runtime provider data.
- Export operator-controlled evidence bundles for snapshots, findings, topology, reviews, and runtime summaries.
- Validate the integrated local-only path on Raspberry Pi/Linux using sanitized records.

## Medium-Term Work

- Harden service-management packaging for long-running agents.
- Expand dashboard usability while preserving the terminal-first product direction.
- Add operator-friendly import/export flows for telemetry and advisory packets.
- Improve enterprise workflow documentation around organizations, roles, quotas, and sync manifests.

## Long-Term Vision

PortMap-AI aims to become an AI-native network observability, exposure management, telemetry intelligence, and remediation orchestration platform supporting local, distributed, and enterprise-scale deployments.

## References

- `PORTMAP_AI_HANDOFF.md`
- `PORTMAP_AI_CODEX_PHASE_19_40_HANDOFF.md`
- `docs/PHASE_HISTORY.md`
- `docs/MILESTONE_INTEGRATION.md`
- `docs/PHASE_59_64_PLAN.md`
- `docs/event_pipeline.md`
- `docs/local_storage.md`
- `docs/runtime_scheduler.md`
- `docs/node_coordination.md`
- `docs/local_api.md`
- `docs/dashboard_foundation.md`
- `docs/persistent_topology_state.md`
- `docs/topology_timeline_views.md`
- `docs/policy_review_engine.md`
- `docs/distributed_visibility_aggregation.md`
- `docs/behavior_correlation.md`
- `docs/schema_validation_engine.md`
- `docs/metadata_stream_parser.md`
- `docs/plugin_registry.md`
- `docs/diagnostic_relay_simulator.md`
- `docs/service_installer_templates.md`
- `docs/archive/`
