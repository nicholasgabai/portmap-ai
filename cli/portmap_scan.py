import logging
from logging.handlers import RotatingFileHandler

import socket
import psutil
import argparse
import json
import requests
import csv
import os
import signal
import sys
import time

from rich.console import Console
from rich.table import Table
from remediator import remediate, execute_actions


# Safe cross-platform log directory
log_dir = os.path.expanduser("~/portmap-ai/logs")
os.makedirs(log_dir, exist_ok=True)

log_path = os.path.join(log_dir, "portmap_ai.log")

log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(log_path, maxBytes=500000, backupCount=3)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger("portmap_ai")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

console = Console()

def get_direction(conn):
    if conn.status == "LISTEN":
        return "Incoming"
    elif conn.raddr:
        return "Outgoing"
    return "Unknown"

def scan_ports(protocol="inet"):
    connections = psutil.net_connections(kind=protocol)
    results = []

    for conn in connections:
        if not conn.laddr:
            continue

        port = str(conn.laddr.port)
        pid = str(conn.pid) if conn.pid else "N/A"
        proc_name = "Unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except Exception:
                pass

        direction = get_direction(conn)
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"

        results.append({
            "port": port,
            "pid": pid,
            "program": proc_name,
            "status": conn.status,
            "direction": direction,
            "local": laddr,
            "remote": raddr
        })

    return results

def export_results(results, export_type, filename):
    if not filename:
        filename = f"scan_export.{export_type}"

    filepath = os.path.join(os.getcwd(), filename)

    if export_type == "json":
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]✔ JSON export saved to {filepath}[/green]")

    elif export_type == "csv":
        keys = results[0].keys() if results else []
        with open(filepath, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        console.print(f"[green]✔ CSV export saved to {filepath}[/green]")

def print_table(results):
    table = Table(title="Port Map")
    table.add_column("Port", justify="right")
    table.add_column("PID", justify="right")
    table.add_column("Program", justify="left")
    table.add_column("Status", justify="left")
    table.add_column("Direction", justify="left")
    table.add_column("Local Address", justify="left")
    table.add_column("Remote Address", justify="left")

    for item in results:
        table.add_row(
            item["port"], item["pid"], item["program"],
            item["status"], item["direction"],
            item["local"], item["remote"]
        )

    console.print(table)

def clear_screen():
    os.system("clear" if os.name == "posix" else "cls")

def handle_sigint(sig, frame):
    console.print("\n[bold red]⏹ Watch mode terminated by user[/bold red]")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="PortMap Scanner with Export + Watch Mode")
    parser.add_argument("--ai", action="store_true", help="Send results to AI agent for analysis")
    parser.add_argument("--protocol", choices=["inet", "tcp", "udp"], default="inet", help="Connection protocol")
    parser.add_argument("--output", choices=["table", "json"], default="table", help="Display output")
    parser.add_argument("--export", choices=["json", "csv"], help="Save output to a file")
    parser.add_argument("--filename", help="Filename to export to")
    parser.add_argument("--watch", action="store_true", help="Enable continuous monitoring")
    parser.add_argument("--interval", type=int, default=3, help="Refresh interval in seconds")

    args = parser.parse_args()
    signal.signal(signal.SIGINT, handle_sigint)

    while True:
        results = scan_ports(protocol=args.protocol)

        if args.ai:
            try:
                response = requests.post("http://localhost:5050/analyze", json=results)
                if response.status_code == 200:
                    analysis = response.json()
                    console.print("[cyan]🤖 AI Agent Response:[/cyan]")
                    console.print(analysis)
                    logger.info(f"AI Response: {analysis}")

                    if analysis.get("recommendation") == "review":
                        for conn in analysis["flagged_connections"]:
                            program = conn.get("program")
                            pid = conn.get("pid")
                            port = conn.get("port")
                            reason = conn.get("reason")

                            user_input = input(f"⚠ Kill {program} (PID {pid}, Port {port})? Reason: {reason} (y/n/skip all): ").lower()

                            if user_input == "y":
                                try:
                                    os.kill(int(pid), signal.SIGKILL)
                                    logger.info(f"Remediated PID {pid} ({program}) - Reason: {reason}")
                                    console.print(f"[green]✔ Killed {program} (PID {pid})[/green]")
                                except Exception as e:
                                    logger.error(f"Failed to kill PID {pid}: {e}")
                                    console.print(f"[red]❌ Failed to kill PID {pid}: {e}[/red]")

                            elif user_input == "skip all":
                                logger.info("User skipped all remaining remediations.")
                                break

                            else:
                                console.print(f"[yellow]⏭ Skipped {program} (PID {pid})[/yellow]")

                else:
                    logger.error(f"AI Agent Error: {response.status_code}")
            except Exception as e:
                logger.exception(f"Could not reach AI agent: {e}")

        if args.export:
            export_results(results, args.export, args.filename)

        clear_screen()

        if args.output == "json":
            print(json.dumps(results, indent=2))
        else:
            print_table(results)

        if not args.watch:
            break

        time.sleep(args.interval)

if __name__ == "__main__":
    main()
