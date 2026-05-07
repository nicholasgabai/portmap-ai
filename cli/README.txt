Purpose: PortMap-AI command-line interfaces.

Primary interface:

```bash
python -m cli.main --help
```

Common commands:

```bash
python -m cli.main scan --output table
python -m cli.main scan --output json
python -m cli.main stack --verbose
python -m cli.main stack --no-dashboard
python -m cli.main tui
python -m cli.main health
python -m cli.main nodes
python -m cli.main metrics
python -m cli.main logs --output-dir ./artifacts
python -m cli.main logs --filter-event-type command_event --tail 10
python -m cli.main config validate core_engine/default_configs/worker_orchestrated.json
python -m cli.main config validate core_engine/default_configs/worker_orchestrated.json --role worker
```

After `pip install -e .`, the same commands are available through the installed `portmap` console command.

The unified CLI wraps existing modules. Lower-level scripts remain available:

- `scripts/run_stack.py`
- `scripts/run_orchestrator.sh`
- `scripts/run_master.sh`
- `scripts/run_worker.sh`
- `scripts/run_dashboard.sh`
- `cli/logs.py`
- `cli/dashboard.py`

The dashboard is a Textual terminal UI. It is launched by `python -m cli.main tui` or by `python -m cli.main stack` unless `--no-dashboard` is passed.
