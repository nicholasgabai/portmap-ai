# Phase 159-164 Packaging And Installers Plan

Milestone AA makes PortMap-AI installable, updateable, and maintainable across supported operating systems while preserving the validated runtime, TUI, and dashboard baseline. This milestone is planning/readiness first: it does not execute installers, change services, request administrator escalation by default, install drivers, add kernel hooks, store credentials, or force host configuration changes.

## Milestone AA: Packaging And Installers

Goal:
Make PortMap-AI installable, updateable, and maintainable across supported operating systems while preserving the validated runtime/TUI baseline and avoiding invasive installers, driver installs, kernel hooks, or forced service changes.

All work should remain:

- planning/readiness-model first
- export-safe
- rollback-aware
- uninstall-preview aware
- cross-platform ready for Windows, macOS, Linux, and Raspberry Pi/Linux ARM
- compatible with existing `portmap stack`, `portmap tui`, and current dashboard behavior
- free of forced install actions, service changes without operator approval, admin escalation by default, driver/kernel hooks, credential storage, and private identifiers in docs or exports

## Current Starting Point

Implemented foundation available before Phase 159:

- Milestone T provides production runtime profiles, service lifecycle readiness previews, deployment manifests, upgrade/migration readiness, backup/restore planning, and deployment operator summaries.
- Milestone U provides secure identity, transport, configuration, RBAC, tamper detection, secure update, and rollback readiness models.
- Milestone V provides live runtime bridge telemetry into flow/topology summaries while preserving source-mode and metadata-only safety.
- Milestone X provides visualization/operator summary models and the current dashboard/TUI baseline.
- Milestone Z provides scalability readiness, edge worker modes, and cloud relay readiness previews for larger deployments.
- Existing packaging metadata includes docs, configs, service templates, scripts, CLI entry points, and test coverage for installable artifacts.

Milestone AA should turn readiness records into installer and package planning contracts before any real installer execution is introduced.

## Roadmap UI Rule

If a future phase introduces operator-visible data that cannot be clearly validated on the current dashboard, add TUI tabbed navigation before continuing that feature. Do not keep adding crowded dashboard panels.

This rule preserves the current dashboard behavior while keeping operator validation practical as packaging, installer, updater, and deployment-wizard records expand.

## Phase 159 - Windows Installer

Status: Complete baseline

Goal:
Model Windows installer readiness, PowerShell install plan previews, Windows service install previews, shortcut previews, and uninstall/rollback previews without executing an installer.

Build:

- `core_engine/packaging/installer_previews.py`
- `core_engine/packaging/windows_installer.py`
- `tests/test_windows_installer_readiness.py`
- `docs/windows_installer_readiness.md`

Features:

- Windows installer readiness records.
- PowerShell, MSI, ZIP app, and winget install plan previews.
- Windows service install previews.
- Start Menu and Desktop shortcut previews.
- Uninstall and rollback previews.
- Export-safe Windows packaging validation summaries.

Acceptance:

- No actual installer is executed.
- No Windows service is installed, started, stopped, or changed.
- No administrator escalation is requested by default.
- No registry, firewall, process, service, driver, or kernel-hook changes are made.
- No PATH modification, filesystem write, credential storage, or command execution is performed.
- Uninstall and rollback previews are included before any future install action can be considered.

## Phase 160 - macOS Packaging

Status: Complete baseline

Goal:
Model macOS app/package readiness, launchd previews, signing/notarization readiness, app bundle/package layout previews, and uninstall/rollback previews without signing, notarizing, or installing packages.

Build:

- `core_engine/packaging/macos_layouts.py`
- `core_engine/packaging/macos_packaging.py`
- `tests/test_macos_packaging_readiness.py`
- `docs/macos_packaging_readiness.md`

Features:

- macOS layout preview records for app bundle, pkg installer, launchd service, and CLI-only paths.
- macOS packaging readiness records for app bundle, pkg, dmg, Homebrew, and CLI-only package methods.
- launchd service previews.
- Signing readiness summaries.
- Notarization readiness summaries.
- Uninstall and rollback previews.
- Export-safe macOS packaging validation summaries.

Acceptance:

- No signing or notarization is performed.
- No package is installed.
- No launchd service is loaded, started, stopped, or changed.
- No admin escalation is requested by default.
- No package, app bundle, plist, filesystem, launchd, signing, notarization, driver, kernel-hook, credential, or runtime behavior change is performed.
- Existing `portmap stack`, `portmap tui`, and dashboard behavior remain unchanged.

## Phase 161 - Linux Packaging

Status: Complete baseline

Goal:
Model Linux deb/rpm/package readiness, systemd user/service previews, path/layout validation, uninstall/rollback previews, and Raspberry Pi/Linux ARM packaging notes without publishing or installing packages.

Build:

- `core_engine/packaging/linux_layouts.py`
- `core_engine/packaging/linux_packaging.py`
- `tests/test_linux_packaging_readiness.py`
- `docs/linux_packaging_readiness.md`

Features:

- Linux layout preview records for DEB, RPM, tarball, systemd service, and CLI-only paths.
- Linux packaging readiness records for DEB, RPM, tarball, APT repository, and CLI-only package methods.
- systemd service previews.
- Raspberry Pi readiness summaries.
- Linux ARM readiness summaries.
- Uninstall and rollback previews.
- Export-safe Linux packaging validation summaries.

Acceptance:

- No package is published or installed.
- No systemd unit is installed, enabled, started, stopped, or changed.
- No service, firewall, process, driver, or kernel-hook change is made.
- Raspberry Pi/Linux ARM constraints are explicitly represented.
- Uninstall and rollback previews are included.
- No package generation, repository publishing, filesystem write, systemd write, service creation, admin escalation, credential storage, private identifier export, or runtime behavior change is performed.

## Phase 162 - Container Deployment

Status: Planned

Goal:
Model Docker and Compose readiness, container profile previews, volume/network/environment layout summaries, and resource-limit recommendations without publishing images or changing host/container runtime state.

Build:

- Docker and Compose readiness records.
- Container profile previews.
- Volume, network, and environment layout summaries.
- Resource limit recommendations.
- Export-safe container deployment summaries.

Acceptance:

- No registry publishing is performed.
- No image is built, pushed, pulled, or run by default.
- No container network, volume, environment, firewall, or service state is changed.
- Resource limits remain advisory recommendations.
- Existing runtime and TUI commands remain unchanged.

## Phase 163 - Secure Auto-Updater

Status: Planned

Goal:
Model update channels, version/checksum/signature readiness, rollback readiness, and staged-update previews without automatic update execution.

Build:

- Update channel records.
- Version, checksum, and signature readiness records.
- Rollback readiness records.
- Staged-update previews.
- Export-safe updater summaries.

Acceptance:

- No automatic updates run.
- No downloads, installer execution, service changes, migrations, or rollbacks are performed.
- No credentials, private keys, signing keys, or secrets are stored.
- Update and rollback records are preview-only until explicit future operator approval paths exist.
- Existing secure update and rollback models remain advisory-first.

## Phase 164 - Deployment Wizard

Status: Planned

Goal:
Model guided deployment wizard states, setup records, environment checks, profile selection, and installation summaries without destructive install actions.

Build:

- Deployment wizard state models.
- Guided setup records.
- Environment check summaries.
- Profile selection records.
- Installation summary records.
- Optional TUI screens only if needed for validation.
- Export-safe deployment wizard summaries.

Acceptance:

- No destructive install actions are executed.
- No service, firewall, process, package, container, update, or credential state is changed.
- Profile selection remains advisory unless a future operator-approved installer phase explicitly enables action.
- TUI tabbed navigation is added first if wizard data cannot be validated clearly on the current dashboard.
- Existing `portmap stack`, `portmap tui`, and dashboard behavior remain preserved.

## Safety Boundaries

Milestone AA must not:

- execute installers
- force install actions
- change services without operator approval
- request admin escalation by default
- install drivers or kernel hooks
- publish packages or containers
- run automatic updates
- perform destructive uninstall, rollback, migration, or cleanup actions
- modify firewall, process, service, routing, collection, or worker state
- store credentials, certs, keys, signing secrets, or private identifiers
- expose private identifiers in docs or exports
- break existing `portmap stack`, `portmap tui`, or current dashboard behavior

## Validation Checklist

- Windows, macOS, Linux, Raspberry Pi/Linux ARM, container, updater, and wizard records are preview-only.
- Installer, service, shortcut, launchd, systemd, package, container, updater, uninstall, and rollback records are export-safe.
- No admin escalation, service changes, driver installs, kernel hooks, package publishing, registry publishing, automatic updates, or destructive actions are introduced.
- Current runtime, TUI, dashboard, CLI entry points, packaging metadata, and docs packaging remain valid.
- The roadmap UI rule is followed before adding crowded operator-visible dashboard data.
- Sensitive-data scans and artifact/private-file checks are clean before commit.

Milestone AA should make PortMap-AI easier to install and maintain without crossing from readiness models into host-changing installer behavior until separate operator-approved implementation phases explicitly authorize it.
