# Windows Installer Readiness

Phase 159 adds Windows installer readiness models for future Windows distribution work. The implementation defines install plan previews, PowerShell setup previews, MSI/ZIP/winget paths, Windows service previews, shortcut previews, uninstall previews, rollback previews, and validation summaries without creating installers, executing PowerShell, modifying PATH, creating services, writing registry keys, writing files, or requesting administrator escalation.

## Installer Preview Records

`core_engine.packaging.installer_previews` defines generic installer preview records used by Windows installer readiness and future packaging phases. Supported preview types are `install`, `service_install`, `shortcut_create`, `uninstall`, `rollback`, `validation`, and `unknown`.

Each preview includes a sanitized command preview, required permissions, rollback and uninstall availability, validation steps, safety warnings, advisory notes, and fixed safety flags. Command previews are display-only strings. They are sanitized for export safety and are never executed.

## Windows Readiness Records

`core_engine.packaging.windows_installer` defines Windows installer readiness summaries with:

- install steps
- service preview
- shortcut preview
- uninstall preview
- rollback preview
- validation summary
- required permission summaries
- admin and signing requirement summaries

Supported installer states are `ready`, `degraded`, `blocked`, `unavailable`, and `unknown`. Supported install methods are `powershell_preview`, `msi_preview`, `zip_app_preview`, `winget_preview`, and `unknown`.

## Preview Paths

The PowerShell preview path models a script-based setup plan with `-WhatIf` style semantics. The MSI preview path models future MSI install command shape only. The ZIP app preview path models archive extraction layout only. The winget preview path models a future package-manager path only.

None of these paths creates an installer, downloads packages, executes commands, modifies PATH, writes registry keys, creates services, or changes runtime behavior.

## Service And Shortcut Previews

Windows service previews describe the future service name, executable placeholder, required permissions, validation steps, and rollback/uninstall availability. They do not create, start, stop, or modify a Windows service.

Shortcut previews describe future Start Menu and Desktop shortcut behavior. They do not create shortcuts or write files.

## Uninstall And Rollback

Uninstall and rollback previews are required before any future installer action can be considered. They describe review steps and command shape only. No files are deleted, no services are removed, no registry keys are changed, and no rollback restore or overwrite is performed.

## Safety Boundary

Phase 159 remains readiness-only:

- No installer generation.
- No PowerShell execution.
- No filesystem writes.
- No Windows service creation or modification.
- No registry writes.
- No PATH modification.
- No administrator escalation.
- No driver or kernel hook installation.
- No credential storage.
- No private identifier export.

## Future Phases

Phase 160 macOS packaging, Phase 161 Linux packaging, Phase 162 container deployment, Phase 163 secure auto-updater, and Phase 164 deployment wizard can reuse installer preview records for command previews, validation steps, rollback/uninstall summaries, and safety warnings while keeping all package work advisory until an explicit operator-approved install path is added.
