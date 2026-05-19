# Unified Configuration Profiles

Unified runtime configuration profiles describe how local PortMap-AI runtime primitives should be composed for operator-triggered workflows. They are planning and configuration records only; loading a profile does not start services, run scans, execute remediation, contact external systems, or change host configuration.

## Profile Types

Supported profile types:

- `default` - balanced local defaults for dry-run workflows.
- `edge-device` - resource-conscious settings for Raspberry Pi and Linux edge devices.
- `operator` - operator-provided overrides merged onto a built-in profile.

Supported runtime modes:

- `dry-run`
- `local-write`
- `service-preview`

The default profile uses `dry-run`.

## Included Settings

A runtime profile can summarize defaults for:

- Runtime components.
- Scheduler intervals.
- Local SQLite storage settings.
- Local read-only API binding.
- Dashboard provider settings.
- Operational export settings.
- Optional node configuration records that are validated with the existing configuration validator.

Profiles include the standard safety fields:

- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

## Example

```python
from core_engine.runtime import default_runtime_profile, merge_runtime_profiles

profile = merge_runtime_profiles(
    default_runtime_profile(),
    {
        "profile_id": "operator-profile",
        "name": "Operator Profile",
        "api": {"enabled": True},
        "scheduler": {
            "jobs": {
                "event_flush": {"enabled": True}
            }
        }
    },
)
```

The merge keeps default scheduler, storage, dashboard, and export settings while applying only the operator-provided overrides.

## JSON Import And Export

Profiles can be imported from or exported to explicit operator-provided local files. The helper creates parent directories when saving to a selected output location, but it does not install services or modify runtime state.

```python
from core_engine.runtime import load_runtime_profile, save_runtime_profile_file

profile = load_runtime_profile(builtin="edge-device")
save_runtime_profile_file(profile, "operator-selected-profile-output.json")
```

## Validation

Profile validation checks:

- Required profile identifiers and names.
- Supported profile types.
- Supported runtime modes.
- Component lists.
- Scheduler intervals.
- Storage backend fields.
- Local API host and port fields.
- Dashboard provider fields.
- Export redaction fields.
- Embedded node configs through the existing PortMap-AI config validator.

Validation is local-only and does not start any runtime process.

## Raspberry Pi Notes

The edge-device profile uses longer default intervals and disabled dashboard/static output defaults to keep resource usage modest. Operators can still override settings explicitly for their own local environment.
