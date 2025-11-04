"""CLI utility for exporting PortMap-AI audit logs."""

from __future__ import annotations

import argparse
import sys

from core_engine.log_exporter import export_logs


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export PortMap-AI logs and state data")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write the log archive (defaults to ~/.portmap-ai/logs/exports)",
    )
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="Exclude state JSON files from the archive",
    )
    args = parser.parse_args(argv)

    archive_path = export_logs(output_dir=args.output_dir, include_state=not args.no_state)
    print(f"📦 Log archive created at {archive_path}")


if __name__ == "__main__":
    main(sys.argv[1:])
