#!/usr/bin/env python3
"""Convenience launcher to start orchestrator, master, and worker together."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_ORCHESTRATOR_CFG = ROOT_DIR / "tests" / "node_configs" / "orchestrator.json"
DEFAULT_MASTER_CFG = ROOT_DIR / "tests" / "node_configs" / "master1.json"
DEFAULT_WORKER_CFG = ROOT_DIR / "tests" / "node_configs" / "worker_orchestrated.json"


def build_env() -> dict:
    env = os.environ.copy()
    py_path = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{ROOT_DIR}{os.pathsep}{py_path}" if py_path else str(ROOT_DIR)
    return env


def launch(module: str, args: List[str], env: dict) -> subprocess.Popen:
    cmd = [sys.executable, "-m", module, *args]
    return subprocess.Popen(cmd, env=env)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run orchestrator, master, and worker together")
    parser.add_argument("--orchestrator-config", default=str(DEFAULT_ORCHESTRATOR_CFG), help="Path to orchestrator config JSON")
    parser.add_argument("--master-config", default=str(DEFAULT_MASTER_CFG), help="Path to master config JSON")
    parser.add_argument("--worker-config", default=str(DEFAULT_WORKER_CFG), help="Path to worker config JSON")
    parser.add_argument("--worker-args", nargs=argparse.REMAINDER, help="Extra args for worker module (placed after --config)")
    args = parser.parse_args()

    env = build_env()
    processes: List[subprocess.Popen] = []

    try:
        proc_orch = launch("core_engine.orchestrator", ["--config", args.orchestrator_config], env)
        processes.append(proc_orch)
        print("[+] Orchestrator started (PID %s)" % proc_orch.pid)

        proc_master = launch("core_engine.master_node", ["--config", args.master_config], env)
        processes.append(proc_master)
        print("[+] Master started (PID %s)" % proc_master.pid)

        worker_launch_args = ["--config", args.worker_config]
        if args.worker_args:
            worker_launch_args.extend(args.worker_args)
        proc_worker = launch("core_engine.worker_node", worker_launch_args, env)
        processes.append(proc_worker)
        print("[+] Worker started (PID %s)" % proc_worker.pid)

        print("\nPress Ctrl+C to stop all processes.")
        while True:
            # exit loop if any process stops unexpectedly
            if any(proc.poll() is not None for proc in processes):
                break
            time.sleep(0.5)
   except KeyboardInterrupt:
        print("\n[!] Stopping services...")
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        print("[+] All services stopped.")


if __name__ == "__main__":
    main()
