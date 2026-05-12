# PortMap-AI Roadmap

This roadmap summarizes the current direction after the Phase 45 baseline. `PORTMAP_AI_HANDOFF.md` remains the canonical implementation record, and `docs/PHASE_HISTORY.md` summarizes completed phase groups.

## Current Baseline

Phases 0-45 are implemented locally in the working tree and documented as complete baselines. A complete baseline means the foundational implementation is operational and tested, while future work may expand depth, integrations, and production hardening.

## Near-Term Work

- Follow the Phase 44-53 local infrastructure visibility plan in `docs/PHASE_44_53_PLAN.md`.
- Use the local event pipeline in `docs/event_pipeline.md` as the event-history foundation for future storage, dashboard, and correlation work.
- Use the local SQLite storage layer in `docs/local_storage.md` for durable events, snapshots, assets, services, topology relationships, and findings.
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
- `docs/PHASE_44_53_PLAN.md`
- `docs/event_pipeline.md`
- `docs/local_storage.md`
- `docs/master_roadmap.md`
- `docs/real_device_validation.md`
