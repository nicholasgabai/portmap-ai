# Deployment Operator Summary

Phase 122 adds a unified deployment operator summary for Milestone T. It combines deployment runtime profiles, service lifecycle readiness, deployment manifests, upgrade and migration readiness, and backup/restore planning into one dashboard/API/export-safe deployment readiness view.

This phase is advisory and dry-run only. It does not install services, execute deployments, modify configs, create backups, restore files, modify firewall rules, store credentials, or write host configuration.

## Readiness Model

Deployment summaries roll up:

- production runtime profiles
- service lifecycle readiness
- deployment manifests
- upgrade and migration readiness
- backup and restore planning
- cross-platform compatibility

The unified `deployment_state` can be:

- `ready` - supplied dry-run records are ready for operator release review.
- `degraded` - deployment may proceed only after operator review of degraded components.
- `blocked` - one or more components blocks deployment readiness.
- `unknown` - one or more required summaries is missing or malformed.

The `readiness_score` is a bounded 0-100 score derived from component states. It is advisory only and does not trigger automation.

## Release Checklist

The release-readiness checklist asks the operator to review:

- production runtime profile compatibility
- service lifecycle previews and permission requirements
- deployment manifests and platform placeholders
- upgrade, migration, rollback, and backup requirements
- backup and restore plans
- macOS, Linux, Raspberry Pi, and Windows compatibility summaries

Checklist items do not install, start, stop, restore, migrate, or write anything.

## Operator Views

`core_engine.deployment.operator_views` builds:

- summary cards
- readiness checklist rows
- deployment recommendations
- cross-platform compatibility rollups
- edge/Raspberry Pi readiness rollups
- Windows/macOS/Linux readiness rollups
- backup/restore readiness rollups
- migration readiness rollups

The views are safe for local dashboards and API responses. They do not include hostnames, IP addresses, usernames, MAC addresses, credentials, logs, screenshots, private paths, databases, or runtime artifacts.

## What Remains Before Real Production Deployment

Milestone T records are deployment planning primitives. Before real production deployment, operators still need externally reviewed procedures for service installation, upgrade execution, backup creation, restore validation, release packaging, platform-specific hardening, and operational support. PortMap-AI keeps these records local-first, operator-controlled, preview-only, and export-safe.
