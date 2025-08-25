import sys
import time
import argparse
import logging
import json
import os
from pathlib import Path

# Add ai_agent to sys.path for analyzer_stub import
sys.path.append(str(Path(__file__).resolve().parents[1] / "ai_agent"))

from portmap_scan import scan_ports
from remediator import remediate
from analyzer_stub import analyze_connections

# Constants and Config Paths
BASE_DIR = Path.home() / ".portmap-ai"
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
SETTINGS_FILE = BASE_DIR / "settings.json"
SKIP_CACHE_FILE = DATA_DIR / "skip_cache.json"
SEEN_CACHE_FILE = DATA_DIR / "seen_cache.json"
POLICY_FILE = DATA_DIR / "firewall_policy.json"
DECISION_LOG_FILE = DATA_DIR / "decision_log.json"
PROGRAM_STATS_FILE = DATA_DIR / "program_stats.json"
POLICY_CONFIG_FILE = DATA_DIR / "policy_config.json"

VERSION = "1.0.0"
AUTOLEARN_THRESHOLD = 3
ENABLE_AUTOLEARN = False

# Bootstrap directories
for directory in [LOG_DIR, DATA_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Logging Setup
logger = logging.getLogger("realtime_agent")
logger.setLevel(logging.INFO)
log_file = LOG_DIR / "realtime_agent.log"
handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Helper Functions
def load_json(filepath, default):
    try:
        if filepath.exists():
            with open(filepath, "r") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load {filepath}: {e}")
    return default

def save_json(filepath, data):
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.warning(f"Failed to save {filepath}: {e}")

def load_policy_config():
    config = load_json(POLICY_CONFIG_FILE, default={})
    return config.get("whitelist", []), config.get("blacklist", [])

def save_policy_config(whitelist, blacklist):
    save_json(POLICY_CONFIG_FILE, {"whitelist": whitelist, "blacklist": blacklist})

def is_policy_match(conn, policy_list):
    return any(conn.get('program') == rule.get('program') and conn.get('reason') == rule.get('reason') for rule in policy_list)

def update_program_stats(conn, action):
    stats = load_json(PROGRAM_STATS_FILE, default={})
    key = f"{conn['program']}|{conn.get('reason', 'unknown')}"
    entry = stats.get(key, {"seen": 0, "remediated": 0, "skipped": 0, "last_seen": None})

    entry["seen"] += 1
    if action == "remediated":
        entry["remediated"] += 1
    elif action == "skipped":
        entry["skipped"] += 1
    entry["last_seen"] = time.strftime('%Y-%m-%d %H:%M:%S')
    stats[key] = entry
    save_json(PROGRAM_STATS_FILE, stats)

def log_decision(conn, decision):
    log = load_json(DECISION_LOG_FILE, default=[])
    log.append({
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "program": conn["program"],
        "pid": conn["pid"],
        "port": conn["port"],
        "reason": conn.get("reason", "unknown"),
        "decision": decision
    })
    save_json(DECISION_LOG_FILE, log)

def apply_policy_actions(flagged, whitelist, blacklist, skip_cache):
    auto_actions = []
    remaining = []
    for conn in flagged:
        if is_policy_match(conn, whitelist):
            logger.info(f"Auto-skip {conn['program']} on port {conn['port']}")
            skip_cache.add((conn['pid'], conn['port']))
            update_program_stats(conn, "skipped")
            log_decision(conn, "auto-skip")
        elif is_policy_match(conn, blacklist):
            logger.info(f"Auto-remediate {conn['program']} on port {conn['port']}")
            remediate(conn)
            update_program_stats(conn, "remediated")
            log_decision(conn, "auto-remediate")
        else:
            remaining.append(conn)
    return remaining

def prompt_user_and_remediate(flagged, skip_cache, seen_connections):
    for conn in flagged:
        conn_id = (conn['pid'], conn['port'])
        if conn_id in skip_cache or conn_id in seen_connections:
            continue

        print(f"\n⚠ Suspicious: {conn['program']} (PID {conn['pid']}, Port {conn['port']}) - Reason: {conn.get('reason', 'unknown')}")
        choice = input("Remediate? [y]es / [n]o / [a]ll / [s]kip all / [e]xit: ").lower()

        if choice == 'y':
            remediate(conn)
            update_program_stats(conn, "remediated")
            log_decision(conn, "user-remediate")
        elif choice == 'n':
            update_program_stats(conn, "skipped")
            log_decision(conn, "user-skip")
        elif choice == 'a':
            for rem in flagged:
                remediate(rem)
                update_program_stats(rem, "remediated")
                log_decision(rem, "user-remediate-all")
            break
        elif choice == 's':
            for rem in flagged:
                skip_cache.add((rem['pid'], rem['port']))
                update_program_stats(rem, "skipped")
                log_decision(rem, "user-skip-all")
            print("✔ Skipped all remaining entries.")
            break
        elif choice == 'e':
            print("🛑 Exiting remediation prompt.")
            break
        seen_connections.add(conn_id)

def run_realtime_agent(mode, interval):
    print(f"🛰 Running PortMap AI Agent in {mode.upper()} mode with {interval}s interval...\n")
    skip_cache = set(load_json(SKIP_CACHE_FILE, default=[]))
    seen_connections = set()
    try:
        while True:
            connections = scan_ports()
            enriched = analyze_connections(connections)
            whitelist, blacklist = load_policy_config()
            flagged = [c for c in enriched if not is_policy_match(c, whitelist)]
            visible = apply_policy_actions(flagged, whitelist, blacklist, skip_cache)
            actionable = [c for c in visible if (c['pid'], c['port']) not in skip_cache and (c['pid'], c['port']) not in seen_connections and 'reason' in c]

            if actionable:
                print(f"⚠️ Detected {len(actionable)} suspicious connections")
                if mode == "prompt":
                    prompt_user_and_remediate(actionable, skip_cache, seen_connections)
            else:
                print(f"✅ No suspicious connections needing remediation")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"🛑 Agent stopped by user.")
    save_json(SKIP_CACHE_FILE, list(skip_cache))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🛰 PortMap AI Realtime Agent")
    parser.add_argument("--mode", choices=["prompt", "silent"], default="prompt", help="Interaction mode")
    parser.add_argument("--interval", type=int, default=10, help="Scan interval in seconds")
    parser.add_argument("--version", action="version", version=f"PortMap AI v{VERSION}")
    args = parser.parse_args()

    run_realtime_agent(args.mode, args.interval)
