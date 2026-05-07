"""CLI utility for exporting PortMap-AI audit logs."""

from __future__ import annotations

import argparse
import json
import sys

from core_engine.log_exporter import export_logs, filter_audit_events


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export PortMap-AI logs and state data")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write the log archive (defaults to settings.export_dir or ~/Downloads/portmap-ai-exports)",
    )
    parser.add_argument(
        "--no-state",
        action="store_true",
        help="Exclude state JSON files from the archive",
    )
    parser.add_argument("--filter-node", help="Print JSONL audit events for a node instead of creating an archive")
    parser.add_argument("--filter-event-type", help="Print JSONL audit events by event_type instead of creating an archive")
    parser.add_argument("--tail", type=int, default=None, help="Limit filtered audit output to the last N events")
    args = parser.parse_args(argv)

    if args.filter_node or args.filter_event_type or args.tail is not None:
        print(
            json.dumps(
                filter_audit_events(
                    node_id=args.filter_node,
                    event_type=args.filter_event_type,
                    limit=args.tail,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    archive_path = export_logs(output_dir=args.output_dir, include_state=not args.no_state)
    print(f"📦 Log archive created at {archive_path}")
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
