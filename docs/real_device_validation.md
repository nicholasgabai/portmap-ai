# Real Device Validation

Use this checklist before claiming runtime support for a real device class. Record host model, OS version, Python version, install method, command output summaries, and any deviations.

## Raspberry Pi / Linux Checklist

- Install Python environment and dependencies.
- Run `portmap setup`.
- Run `portmap doctor`.
- Run `portmap stack --no-dashboard --verbose`.
- Run `portmap tui`.
- Confirm worker registration in the orchestrator.
- Confirm heartbeat validation through `/nodes` or `portmap nodes`.
- Confirm logging validation under `~/.portmap-ai/logs`.
- Run service detection against an authorized local endpoint.
- Confirm graceful shutdown of stack processes.
- Export logs with `portmap logs`.

## Raspberry Pi Validation Results

Validated with redacted local environment details:

- Platform: Raspberry Pi Linux ARM64/aarch64.
- Python: 3.11.2.
- Tests: 367 passed.
- Local username/path: `<REDACTED_LOCAL_USER_PATH>`.
- Local IP: `<REDACTED_LAN_IP>`.
- Gateway: `<REDACTED_GATEWAY_IP>`.
- MAC addresses: not included.
- Screenshots: not included.

Do not add personal usernames, LAN IPs, MAC addresses, local absolute paths, tokens, secrets, or screenshots to this validation record.

## macOS Checklist

- Install Python environment and dependencies.
- Run `portmap setup`.
- Run `portmap doctor`.
- Run `portmap stack --no-dashboard --verbose`.
- Run `portmap tui`.
- Confirm worker registration in the orchestrator.
- Confirm heartbeat validation through `/nodes` or `portmap nodes`.
- Confirm logging validation under `~/.portmap-ai/logs`.
- Run service detection against an authorized local endpoint.
- Confirm graceful shutdown of stack processes.
- Export logs with `portmap logs`.

## Windows Validation

Pending external Windows validation. Do not mark Windows runtime support as verified until test results are returned.

Checklist to run when a Windows test host is available:

- Install Python environment and dependencies.
- Run `portmap setup`.
- Run `portmap doctor`.
- Run `portmap stack --no-dashboard --verbose`.
- Run `portmap tui`.
- Confirm worker registration in the orchestrator.
- Confirm heartbeat validation through `/nodes` or `portmap nodes`.
- Confirm logging validation under `~/.portmap-ai/logs`.
- Run service detection against an authorized local endpoint.
- Confirm graceful shutdown of stack processes.
- Export logs with `portmap logs`.
