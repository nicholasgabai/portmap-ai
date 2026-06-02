# Secure Config And Secrets Management

Phase 125 adds secure configuration and secrets-management readiness records for PortMap-AI runtime environments.

This phase is advisory and preview-only. It does not store real secrets, create encryption keys, write secrets to disk, integrate OS keychains, perform live encryption, exchange credentials, or modify runtime authentication.

## Secure Configuration Philosophy

PortMap-AI should separate runtime configuration posture from secret material. Phase 125 models whether an environment is ready for safer secret handling without implementing live encryption or provider integration.

`core_engine/security/secure_config.py` defines `SecureConfigProfile` records for:

- `development`
- `staging`
- `production`
- `edge`
- `ephemeral_runtime`

Profiles include:

- `config_profile_name`
- `secret_storage_mode`
- `encryption_required`
- `rotation_supported`
- `persistence_mode`
- `bootstrap_mode`
- `export_safety`
- `downgrade_risk`
- `operator_actions_required`
- `advisory_notes`

Supported export-safety states:

- `insecure`
- `degraded`
- `recommended`
- `required`

Every exported profile carries explicit safety fields:

- `export_safe: true`
- `dry_run_only: true`
- `live_encryption_enabled: false`
- `os_keychain_integrated: false`
- `plaintext_secret_persistence_allowed: false`
- `credentials_stored: false`

## Current Advisory-Only Secret Handling

`core_engine/security/secrets.py` defines `SecretManagementPreview` records for:

- orchestrator tokens
- worker enrollment secrets
- future mTLS materials
- API/session tokens
- runtime encryption keys

Supported storage readiness modes:

- `ephemeral`
- `memory_only`
- `encrypted_storage_ready`
- `external_secret_provider_ready`

Secret previews include:

- `secret_class`
- `storage_mode`
- `plaintext_allowed`
- `rotation_ready`
- `expiration_supported`
- `exposure_risk`
- `mitigation_summary`
- `preview_only`
- `destructive_action`

`plaintext_allowed` must remain false. The preview records reject imported dictionaries that claim a real secret was generated, a credential was stored, plaintext was persisted, an OS credential store was modified, or a live secret exchange occurred.

## Future Encrypted Runtime Plans

Future phases can build on these records to add protected configuration loading, encrypted local storage, key rotation workflows, external secret provider integration, and runtime secret isolation.

Those phases must still avoid committing real tokens, private keys, certificates, hostnames, IP addresses, usernames, MAC addresses, logs, screenshots, runtime databases, cache files, or private validation notes.

## Secret Rotation Goals

Phase 125 marks whether rotation is ready or needs operator action. It does not rotate live secrets.

Rotation readiness should eventually support:

- token expiration planning
- worker enrollment secret renewal
- mTLS material rollover
- API/session token lifecycle management
- runtime encryption key rotation

## Plaintext Storage Risks

Plaintext storage is treated as unsafe for production. Development profiles are explicitly marked insecure when they model plaintext development posture. No Phase 125 helper writes plaintext secrets or permits plaintext persistence.

Operators should treat any downgrade toward plaintext storage as a review-triggering event.

## External Secret Provider Support

External provider support is represented as readiness metadata only. Phase 125 does not integrate macOS Keychain, Windows Credential Manager, Linux keyrings, cloud secret stores, or enterprise vaults.

Future provider integration must remain explicit, operator-approved, auditable, and export-safe.
