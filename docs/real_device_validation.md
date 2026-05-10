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
