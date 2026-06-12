# Linux Packaging Readiness

Phase 161 adds Linux packaging readiness models for future DEB, RPM, tarball, APT repository, CLI-only, systemd, Raspberry Pi, and Linux ARM distribution work. The implementation defines layout previews, systemd service previews, architecture readiness summaries, uninstall previews, rollback previews, and validation summaries without creating packages, modifying systemd, writing files, publishing repositories, requesting administrator escalation, or changing runtime behavior.

## Layout Preview Records

`core_engine.packaging.linux_layouts` defines export-safe Linux package layout previews. Supported layout types are `deb_preview`, `rpm_preview`, `tarball_preview`, `systemd_service_preview`, `cli_only_preview`, and `unknown`.

Supported distribution families are `debian`, `ubuntu`, `fedora`, `rhel`, `arch`, `raspberry_pi`, `linux_arm`, `generic_linux`, and `unknown`. Supported install scopes are `user`, `system`, `portable`, and `unknown`.

Each layout record includes a sanitized path preview, package name, included and excluded components, systemd service preview metadata, required permissions, rollback/uninstall availability, advisory notes, and fixed safety flags. Path and service previews are display-only strings and are never used to write files or change services.

## Packaging Readiness Records

`core_engine.packaging.linux_packaging` defines Linux packaging readiness summaries with:

- layout previews
- systemd preview
- Raspberry Pi readiness
- Linux ARM readiness
- uninstall preview
- rollback preview
- validation summary
- required permission and admin requirement summaries

Supported packaging states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`. Supported package methods are `deb_preview`, `rpm_preview`, `tarball_preview`, `apt_repo_preview`, `cli_only_preview`, and `unknown`.

## Preview Paths

The DEB preview models Debian, Ubuntu, Raspberry Pi OS, and compatible package layout readiness. The RPM preview models Fedora, RHEL, and compatible package layout readiness. The tarball preview models portable archive distribution. The APT repository preview models future repository metadata shape only. The CLI-only preview models a terminal-first install path.

None of these paths creates packages, publishes repositories, installs dependencies, writes files, modifies PATH, or changes runtime behavior.

## Raspberry Pi And Linux ARM

Raspberry Pi and Linux ARM readiness summaries describe architecture-aware package constraints, lightweight collector expectations, and future validation notes. They do not build wheels, compile native extensions, deploy workers, change collection, or modify services.

## systemd Preview

systemd previews describe future unit names and command shape only. They do not write unit files, reload daemon state, enable services, start services, stop services, or modify systemd state.

## Uninstall And Rollback

Uninstall and rollback previews are required before future Linux package actions can be considered. They describe review steps and command shape only. No files are deleted, packages removed, repositories changed, services modified, or rollback restores performed.

## Safety Boundary

Phase 161 remains readiness-only:

- No package generation.
- No repository publishing.
- No filesystem writes.
- No systemd unit writes or service changes.
- No administrator escalation.
- No service, firewall, process, driver, or kernel-hook changes.
- No credential storage.
- No private identifier export.

## Future Phases

Phase 162 container deployment, Phase 163 secure auto-updater, and Phase 164 deployment wizard can reuse installer and layout preview patterns for package paths, service previews, validation summaries, rollback/uninstall previews, and safety warnings while keeping all host-changing behavior disabled until an explicit operator-approved install path is added.
