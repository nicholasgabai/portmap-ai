# portmap_agent.py

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_engine.agent_service import BackgroundAgent


def parse_level(level_name: str) -> int:
    try:
        return getattr(logging, level_name.upper())
    except AttributeError:
        raise argparse.ArgumentTypeError(f"Invalid log level '{level_name}'")


def main(argv=None):
    parser = argparse.ArgumentParser(description="PortMap-AI Background Agent")
    parser.add_argument("--config", required=True, help="Path to worker node config JSON")
    parser.add_argument("--log-level", type=parse_level, default=logging.INFO, help="Logging verbosity")
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Override scan interval seconds (falls back to config value when omitted)",
    )
    args = parser.parse_args(argv)

    agent = BackgroundAgent(
        config_path=args.config,
        log_level=args.log_level,
        interval_override=args.interval,
    )
    agent.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
