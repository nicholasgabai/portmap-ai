#!/usr/bin/env python3
"""Compatibility wrapper for the packaged PortMap-AI stack launcher."""

from core_engine.stack_launcher import (  # noqa: F401
    DEFAULT_MASTER_CFG,
    DEFAULT_ORCHESTRATOR_CFG,
    DEFAULT_ORCHESTRATOR_TOKEN,
    DEFAULT_ORCHESTRATOR_URL,
    DEFAULT_WORKER_CFG,
    _listener_pid,
    build_env,
    default_config_path,
    find_stack_port_conflicts,
    format_port_conflicts,
    launch,
    main,
    port_is_listening,
    resolve_stack_runtime,
)


if __name__ == "__main__":
    raise SystemExit(main())
