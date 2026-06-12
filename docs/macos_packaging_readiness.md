# macOS Packaging Readiness

Phase 160 adds macOS packaging readiness models for future app bundle, package, disk image, Homebrew, and CLI-only distribution work. The implementation defines layout previews, launchd service previews, signing readiness, notarization readiness, uninstall previews, rollback previews, and validation summaries without creating packages, signing binaries, notarizing artifacts, writing files, modifying launchd, requesting administrator escalation, or changing runtime behavior.

## Layout Preview Records

`core_engine.packaging.macos_layouts` defines export-safe layout preview records for macOS package planning. Supported layout types are `app_bundle_preview`, `pkg_installer_preview`, `launchd_service_preview`, `cli_only_preview`, and `unknown`. Supported install scopes are `user`, `system`, `portable`, and `unknown`.

Each record includes a sanitized path preview, bundle identifier, app name, included and excluded components, required permissions, rollback/uninstall availability, advisory notes, and fixed safety flags. Path previews are display-only strings and are never used to write files.

## Packaging Readiness Records

`core_engine.packaging.macos_packaging` defines macOS packaging readiness summaries with:

- layout previews
- launchd preview
- signing readiness
- notarization readiness
- uninstall preview
- rollback preview
- validation summary
- required permission and admin requirement summaries

Supported packaging states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`. Supported package methods are `app_bundle_preview`, `pkg_preview`, `dmg_preview`, `homebrew_preview`, `cli_only_preview`, and `unknown`.

## Preview Paths

The app bundle preview models a future `.app` layout. The package preview models future `.pkg` readiness. The disk image preview models a portable `.dmg` layout. The Homebrew preview models formula/cask readiness. The CLI-only preview models a terminal-first install path.

None of these paths creates packages, signs binaries, submits notarization requests, writes files, modifies launchd, changes services, or changes runtime behavior.

## launchd Preview

launchd previews describe future service label and command shape only. They do not write plist files, load services, unload services, start services, stop services, or modify launchd state.

## Signing And Notarization

Signing and notarization readiness records summarize whether future distribution would require a Developer ID identity or notarization configuration. They never store credentials or signing material and never perform signing, notarization submission, ticket stapling, or artifact mutation.

## Uninstall And Rollback

Uninstall and rollback previews are required before future macOS package actions can be considered. They describe review steps and command shape only. No files are deleted, restored, overwritten, or changed.

## Safety Boundary

Phase 160 remains readiness-only:

- No package creation.
- No binary signing.
- No notarization submission or ticket stapling.
- No filesystem writes.
- No launchd plist writes or service changes.
- No administrator escalation.
- No driver or kernel hook installation.
- No credential storage.
- No private identifier export.

## Future Phases

Phase 161 Linux packaging, Phase 162 container deployment, Phase 163 secure auto-updater, and Phase 164 deployment wizard can reuse installer and layout preview patterns for package paths, validation summaries, rollback/uninstall previews, and safety warnings while keeping all host-changing behavior disabled until an explicit operator-approved install path is added.
