# Process And Service Attribution

Phase 94 adds metadata-minimized process and service attribution for enriched flow telemetry. It correlates operator-provided socket and process summaries with flow observations so operators can see which local service appears related to a port or flow.

This feature does not attempt privilege escalation, store raw packet payloads, expose command-line secrets, capture credentials, inject traffic, block traffic, or change host or router settings.

## Inputs

Attribution helpers accept sanitized local records:

- enriched flow observations from Phase 93
- socket summaries with local port, transport, state, and optional process reference
- minimized process summaries with process name and stable process reference
- optional protocol metadata summaries
- platform status fields for unsupported or permission-denied states

The module can also build an explicit best-effort local socket inventory through `core_engine.platform_utils`, but failures degrade safely and do not trigger privilege escalation.

## Minimized Process Metadata

`minimize_process_metadata` keeps only:

- stable `process_ref`
- redacted `pid_ref`
- sanitized process display name
- minimization flags
- removed-field names for auditability

It does not retain usernames, command lines, environment variables, private paths, or secrets.

## Socket Ownership

`build_process_socket_inventory` normalizes listening socket ownership records and links them to minimized process records when available.

Outputs include:

- socket count
- listening socket count
- owned socket count
- process count
- transport and state summaries
- dashboard/API-ready records
- unsupported-platform and permission-denied degraded status fields

## Service Attribution

`build_process_service_attribution_report` correlates enriched flow observations with socket ownership, service-port hints, and optional protocol metadata.

Each attribution record includes:

- flow reference
- service name and port
- process attribution status
- confidence score and confidence level
- match reasons
- sanitized operator display fields

Confidence is advisory. A high score means the available local metadata agrees; it does not authorize enforcement.

## Degraded States

Unsupported platform or permission-denied inputs are reported as degraded summaries:

- `unsupported_platform: true`
- `permission_denied: true`
- `privilege_escalation_attempted: false`
- process attribution status `unsupported` or `permission_denied`

Operators can review these states without exposing private host metadata.

## Safe Example

```python
from core_engine.telemetry import build_process_service_attribution_report

report = build_process_service_attribution_report(
    enriched_flows=enriched_flows,
    socket_records=[
        {
            "transport_protocol": "tcp",
            "local_ip": "198.51.100.20",
            "local_port": 443,
            "status": "LISTEN",
            "process_ref": "process-placeholder",
            "process_name": "sample-service",
        }
    ],
    process_records=[
        {
            "process_ref": "process-placeholder",
            "name": "sample-service",
        }
    ],
    generated_at="2026-01-01T00:00:00+00:00",
)
```

Public examples use documentation-safe placeholder addresses and process names only.
