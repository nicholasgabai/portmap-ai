# Deployment Wizard Readiness

Phase 164 adds metadata-only deployment wizard records for guided setup planning across Windows, macOS, Linux, container, and secure updater readiness. The wizard layer does not install software, modify services, write files, request administrator escalation, download updates, start containers, or change runtime behavior.

## Guided Setup Records

`core_engine/packaging/wizard_states.py` defines deployment wizard step records. Each step includes a step type, step state, selected profile, environment checks, validation steps, rollback availability, uninstall availability, advisory notes, and fixed safety flags.

Supported step types are environment check, platform selection, install method selection, profile selection, service preview, update preview, validation, summary, and unknown. Supported states are complete, pending, blocked, degraded, unavailable, and unknown.

## Unified Summary

`core_engine/packaging/deployment_wizard.py` builds deployment wizard summary records that aggregate:

- Windows installer readiness.
- macOS packaging readiness.
- Linux packaging readiness.
- Container deployment readiness.
- Secure updater readiness.
- Environment, validation, rollback, uninstall, and recommendation summaries.

The summary recommends install methods and profiles without executing them. It keeps rollback and uninstall previews attached so future operator-approved installer phases can validate reversibility before any host-changing action exists.

## Environment Checks

Environment summaries are export-safe and metadata-only. They describe the selected target platform, applicable packaging domains, readiness states, and wizard step counts without storing private identifiers, probing hosts, writing files, or changing collection behavior.

## TUI Screen Rule

If wizard output spans multiple readiness domains or enough steps to crowd the current dashboard, the readiness record recommends a dedicated `deployment_wizard` TUI screen/tab. Phase 164 only records that recommendation; it does not implement new TUI screens.

## Safety Boundary

Deployment wizard records are preview-only and advisory-first. They do not execute installers, create packages, create or modify services, modify launchd/systemd/registry/PATH, start containers, download updates, write files, require admin escalation, store credentials, or modify runtime behavior.

Phase 164 completes the Milestone AA baseline by unifying installer, packaging, container, updater, rollback, uninstall, and validation readiness into a guided deployment planning layer.
