# Legacy Core Engine Modules

The files in this directory capture earlier design experiments for the distributed agent stack (roles, node control, and simulation). They are not used by the current master/worker + orchestrator pipeline but kept for reference.

## Files

- `agent_role.py` — draft utilities for dynamically assigning master/worker roles and handling failover.
- `node_controller.py` — early node registry/message routing abstraction intended to sit between master/worker processes.
- `packet_processor.py` — serialization/validation shim for network packets exchanged across nodes.
- `simulator.py` — sandbox harness for spawning virtual nodes and replaying mocked scans/anomalies.

If you plan to resurrect any of these concepts, consider rebuilding them against the current orchestrator and telemetry services rather than resurrecting the original implementations.
