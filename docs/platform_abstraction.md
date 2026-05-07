# Platform Abstraction

PortMap-AI keeps OS-specific host inspection and process control behind `core_engine.platform_utils`.

Use this module instead of importing `psutil`, checking `os.name`, checking `platform.system()`, or launching Python subprocesses directly from core runtime modules.

Current responsibilities:

- OS, release, CPU architecture, and ARM detection.
- Network interface enumeration.
- Local connection enumeration via `psutil`.
- Process-name lookup by PID.
- Local node address resolution.
- Listener PID and port-listening checks for stack startup.
- Python module launch and subprocess shutdown for the local stack.
- Executable lookup and command execution for platform-specific plugins.
- PID termination and terminal clearing for legacy CLI paths.

The scanner, stack launcher, worker registration, background agent registration, and Linux firewall plugin now route their platform-sensitive work through this layer.

Cross-platform rules:

- Core modules should use `pathlib` for filesystem paths.
- Core modules should call `platform_utils` for host/process/network inspection.
- OS-specific plugins may stay OS-specific, but executable lookup and process execution should still go through `platform_utils`.
- Raspberry Pi support should be treated as Linux ARM support; avoid dependencies or shell commands that are unavailable on ARM unless they are optional plugin behavior.
