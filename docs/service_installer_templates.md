# Service Lifecycle Templates

Phase 58 adds dry-run service lifecycle template generation for operator review. It renders deterministic Linux `systemd` unit text and Windows service command templates, validates placeholder/operator-provided service definitions, and produces structured records for runtime, dashboard, storage, event, policy, timeline, and correlation layers.

This phase does not install services, enable services, start services, change registries, escalate privileges, or modify host configuration.

## What It Provides

- Systemd unit text generation.
- Windows service command template generation.
- Service definition validation.
- Placeholder and operator-provided path handling.
- Environment-file template support.
- Runtime and dashboard summaries.
- Dry-run deployment records.
- Event, storage, policy, timeline, and correlation integration hooks.

## Service Definition

Use sanitized placeholders in public docs and examples:

```json
{
  "service_id": "service.sample.agent",
  "name": "portmap-sample-agent",
  "display_name": "PortMap Sample Agent",
  "description": "Runs the sample local PortMap agent workflow.",
  "command": ["<runtime>", "-m", "portmap_agent", "--config", "<config-file>"],
  "working_directory": "<working-directory>",
  "environment_file": "<environment-file>",
  "user": "<service-user>",
  "metadata": {
    "owner": "operator-placeholder"
  }
}
```

## Generate Templates

```python
from core_engine.installers.service_templates import generate_service_templates

result = generate_service_templates(
    service_definition,
    platforms=["systemd", "windows"],
)
```

The result includes dry-run safety fields:

```json
{
  "classification": "valid",
  "dry_run": true,
  "install_executed": false,
  "service_enabled": false,
  "service_started": false,
  "automatic_changes": false,
  "administrator_controlled": true
}
```

## Systemd Template

The systemd renderer produces reviewable unit text only:

```text
[Unit]
Description=Runs the sample local PortMap agent workflow.
After=network-online.target

[Service]
Type=simple
ExecStart=<runtime> -m portmap_agent --config <config-file>
Restart=on-failure
RestartSec=5
WorkingDirectory=<working-directory>
EnvironmentFile=<environment-file>
User=<service-user>

[Install]
WantedBy=default.target
```

No `systemctl enable`, `systemctl start`, package install, privilege escalation, or file write is performed.

## Windows Template

The Windows renderer produces command text for operator review:

```text
REM Dry-run service template. Review before operator execution.
REM Optional environment file placeholder: <environment-file>
sc.exe create "portmap-sample-agent" binPath= "<runtime>" -m portmap_agent --config "<config-file>" start= demand DisplayName= "PortMap Sample Agent"
sc.exe description "portmap-sample-agent" "Runs the sample local PortMap agent workflow."
REM No service installation, enable, or start action was executed by PortMap-AI.
```

No service is created or started by PortMap-AI in this phase.

## Integration Records

The module exposes helpers for platform integration:

- `build_service_template_event()`
- `build_service_template_finding()`
- `build_service_template_storage_record()`
- `build_service_template_timeline_entry()`
- `build_service_template_dashboard_summary()`
- `build_service_template_correlation_record()`

These records are local-only, JSON serializable, and suitable for later operator review and dashboard display.

## Validation Behavior

Valid service definitions require:

- `service_id`
- `name`
- `description`
- non-empty `command`

`working_directory` and `environment_file` may be placeholders or operator-provided strings. Operator-provided values are accepted but generate review warnings. Invalid values return structured errors instead of throwing unhandled exceptions.

## Lightweight Runtime Notes

Template generation uses standard-library string rendering only. It is suitable for constrained Linux and Raspberry Pi systems because it performs no background work and no host-service operations.
