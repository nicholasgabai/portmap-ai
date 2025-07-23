import time
import requests
import argparse
import logging
import psutil
import json
import os
from remediator import remediate
from portmap_scan import scan_ports

# Setup logging
logger = logging.getLogger("realtime_agent")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("/Users/Nico/portmap-ai/logs/realtime_agent.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

SKIP_CACHE_FILE = "/Users/Nico/portmap-ai/data/skip_cache.json"
SEEN_CACHE_FILE = "/Users/Nico/portmap-ai/data/seen_cache.json"
POLICY_LOG_FILE = "/Users/Nico/portmap-ai/data/firewall_policy.json"
DECISION_LOG_FILE = "/Users/Nico/portmap-ai/data/decision_log.json"
PROGRAM_STATS_FILE = "/Users/Nico/portmap-ai/data/program_stats.json"
POLICY_CONFIG_FILE = "/Users/Nico/portmap-ai/data/policy_config.json"


def ensure_data_directory():
    os.makedirs(os.path.dirname(SKIP_CACHE_FILE), exist_ok=True)

def load_json_file(filepath, as_set=False, as_dict=False):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            data = json.load(f)
            if as_set:
                return set(tuple(x) for x in data)
            if as_dict and isinstance(data, dict):
                return data
            return data
    if as_set:
        return set()
    if as_dict:
        return {}
    return []

def save_json_file(filepath, data):
    ensure_data_directory()
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

def load_policy_config():
    config = load_json_file(POLICY_CONFIG_FILE, as_dict=True)
    if not isinstance(config, dict):
        config = {"whitelist": [], "blacklist": []}
        save_json_file(POLICY_CONFIG_FILE, config)
    return config.get("whitelist", []), config.get("blacklist", [])

def is_policy_match(conn, policy_list):
    for rule in policy_list:
        if conn['program'] == rule.get('program') and conn['reason'] == rule.get('reason'):
            return True
    return False

def update_program_stats(conn, action):
    key = f"{conn['program']}|{conn['reason'].split(' (')[0].strip()}"
    stats = load_json_file(PROGRAM_STATS_FILE, as_dict=True)
    entry = stats.get(key, {"seen": 0, "remediated": 0, "skipped": 0, "last_seen": None})

    entry["seen"] += 1
    if action == "remediated":
        entry["remediated"] += 1
    elif action == "skipped":
        entry["skipped"] += 1

    entry["last_seen"] = time.strftime('%Y-%m-%d %H:%M:%S')
    stats[key] = entry
    save_json_file(PROGRAM_STATS_FILE, stats)

def log_decision(conn, decision):
    log = load_json_file(DECISION_LOG_FILE, as_dict=False)
    if not isinstance(log, list):
        log = []
    log.append({
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "program": conn["program"],
        "pid": conn["pid"],
        "port": conn["port"],
        "reason": conn["reason"],
        "decision": decision
    })
    save_json_file(DECISION_LOG_FILE, log)

def apply_policy_actions(flagged, whitelist, blacklist, skip_cache):
    auto_actions = []
    remaining = []

    for conn in flagged:
        if is_policy_match(conn, whitelist):
            logger.info(f"Auto-skipping {conn['program']} (whitelisted)")
            skip_cache.add((conn['pid'], conn['port']))
            update_program_stats(conn, "skipped")
            log_decision(conn, "auto-skip")
            auto_actions.append((conn, "skipped"))
        elif is_policy_match(conn, blacklist):
            logger.info(f"Auto-remediating {conn['program']} (blacklisted)")
            remediate(conn)
            update_program_stats(conn, "remediated")
            log_decision(conn, "auto-remediate")
            auto_actions.append((conn, "remediated"))
        else:
            remaining.append(conn)

    return remaining, auto_actions

def prompt_user_and_remediate(flagged, skip_cache, seen_connections):
    i = 0
    while i < len(flagged):
        conn = flagged[i]
        conn_id = (conn['pid'], conn['port'])
        if conn_id in skip_cache or conn_id in seen_connections:
            i += 1
            continue

        print(f"\n⚠ Suspicious: {conn['program']} (PID {conn['pid']}, Port {conn['port']}) - Reason: {conn['reason']}")
        choice = input("Remediate? [y]es / [n]o / [a]ll / [s]kip all / [e]xit list: ").lower()

        if choice == 'y':
            remediate(conn)
            update_program_stats(conn, "remediated")
            log_decision(conn, "user-remediate")
        elif choice == 'n':
            update_program_stats(conn, "skipped")
            log_decision(conn, "user-skip")
        elif choice == 'a':
            for j in range(i, len(flagged)):
                remediate(flagged[j])
                update_program_stats(flagged[j], "remediated")
                log_decision(flagged[j], "user-remediate-all")
            break
        elif choice == 's':
            print(f"✔ Skipped remaining {len(flagged) - i} entries.")
            for j in range(i, len(flagged)):
                skip_cache.add((flagged[j]['pid'], flagged[j]['port']))
                update_program_stats(flagged[j], "skipped")
                log_decision(flagged[j], "user-skip-all")
            break
        elif choice == 'e':
            print("🛑 Exiting remediation prompt loop.")
            break

        seen_connections.add(conn_id)
        i += 1

def update_firewall_policy(conn):
    policy_entry = {
        "program": conn['program'],
        "pid": conn['pid'],
        "port": conn['port'],
        "reason": conn['reason'],
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "action": "remediated",
        "times_seen": 1
    }
    policies = load_json_file(POLICY_LOG_FILE)

    updated = False
    for p in policies:
        if (p['program'], p['port']) == (policy_entry['program'], policy_entry['port']):
            p['times_seen'] += 1
            updated = True
            break
    if not updated:
        policies.append(policy_entry)

    save_json_file(POLICY_LOG_FILE, policies)

def log_decision(action, conn, mode):
    entry = {
        "action": action,
        "program": conn['program'],
        "pid": conn['pid'],
        "port": conn['port'],
        "reason": conn['reason'],
        "mode": mode,
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    decision_log = load_json_file(DECISION_LOG_FILE)
    decision_log.append(entry)
    save_json_file(DECISION_LOG_FILE, decision_log)

def send_to_ai_agent(connections):
    try:
        response = requests.post("http://localhost:5050/analyze", json=connections)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"AI Agent Error: {response.status_code}")
            return None
    except Exception as e:
        logger.exception("Failed to reach AI agent")
        return None

def prompt_user_and_remediate(flagged, skip_cache, seen_connections):
    apply_all = False
    i = 0
    total = len(flagged)

    while i < total:
        conn = flagged[i]
        normalized_reason = conn['reason'].split(" (")[0].strip()
        skip_key = (conn['program'].lower(), normalized_reason)
        conn_key = (conn['program'].lower(), conn['pid'], conn['port'])

        if skip_key in skip_cache or conn_key in seen_connections:
            i += 1
            continue

        print(f"\n⚠ Suspicious: {conn['program']} (PID {conn['pid']}, Port {conn['port']}) - Reason: {conn['reason']}")
        decision = input("Remediate? [y]es / [n]o / [a]ll / [s]kip all / [e]xit list: ").strip().lower()

        if decision == "y":
            remediate(conn)
            update_firewall_policy(conn)
            log_decision("remediated", conn, "prompt")
            update_program_stats(conn, "remediated")
            logger.info(f"Remediated PID {conn['pid']} ({conn['program']}) - Reason: {conn['reason']}")
        elif decision == "n":
            logger.info(f"Skipped PID {conn['pid']} ({conn['program']})")
            log_decision("skipped", conn, "prompt")
            update_program_stats(conn, "skipped")
            skip_cache.add(skip_key)
        elif decision == "a":
            logger.info("User selected apply to all.")
            for rem_conn in flagged[i:]:
                remediate(rem_conn)
                update_firewall_policy(rem_conn)
                log_decision("remediated", rem_conn, "prompt")
                update_program_stats(rem_conn, "remediated")
                logger.info(f"Remediated PID {rem_conn['pid']} ({rem_conn['program']}) - Reason: {rem_conn['reason']}")
            return "all"
        elif decision == "s":
            print(f"✔ Skipped remaining {total - i} entries.")
            logger.info(f"User skipped remaining remediations from index {i}.")
            for rem_conn in flagged[i:]:
                norm_reason = rem_conn['reason'].split(" (")[0].strip()
                skip_cache.add((rem_conn['program'].lower(), norm_reason))
                seen_connections.add((rem_conn['program'].lower(), rem_conn['pid'], rem_conn['port']))
                log_decision("skipped", rem_conn, "prompt")
                update_program_stats(rem_conn, "skipped")
            break
        elif decision == "e":
            logger.info("User exited the list early.")
            print("📤 Exiting prompt mode, will check again in next cycle...")
            break
        else:
            print("Invalid input. Enter y, n, a, s, or e.")
            continue

        seen_connections.add(conn_key)
        i += 1

def silent_remediate(flagged):
    for conn in flagged:
        logger.info(f"Auto-remediating: {conn}")
        remediate(conn)
        update_firewall_policy(conn)
        log_decision("remediated", conn, "silent")
        update_program_stats(conn, "remediated")
        logger.info(f"Remediated PID {conn['pid']} ({conn['program']}) - Reason: {conn['reason']}")

def run_realtime_agent(mode, interval):
    print(f"🛰 Running PortMap AI Agent in {mode.upper()} mode with {interval}s interval...")
    logger.info(f"Started agent in {mode} mode")

    skip_cache = load_json_file(SKIP_CACHE_FILE, as_set=True)
    seen_connections = load_json_file(SEEN_CACHE_FILE, as_set=True)
    whitelist, blacklist = load_policy_config()

    try:
        while True:
            results = scan_ports()
            ai_response = send_to_ai_agent(results)
            if ai_response and ai_response.get("recommendation") == "review":
                flagged = ai_response.get("flagged_connections", [])
                new_flagged = []

                for conn in flagged:
                    conn_key = (conn['program'].lower(), conn['pid'], conn['port'])
                    normalized_reason = conn['reason'].split(" (")[0].strip()
                    skip_key = (conn['program'].lower(), normalized_reason)

                    if is_policy_match(conn, whitelist):
                        skip_cache.add(skip_key)
                        seen_connections.add(conn_key)
                        log_decision("whitelisted", conn, mode)
                        update_program_stats(conn, "skipped")
                        continue
                    if is_policy_match(conn, blacklist):
                        remediate(conn)
                        update_firewall_policy(conn)
                        log_decision("blacklisted", conn, mode)
                        update_program_stats(conn, "remediated")
                        seen_connections.add(conn_key)
                        continue

                    if conn_key not in seen_connections and skip_key not in skip_cache:
                        new_flagged.append(conn)

                visible = new_flagged
                if visible:
                    print(f"\n⚠️ Detected {len(visible)} suspicious connections")
                    logger.info(f"Flagged: {visible}")

                    if mode == "prompt":
                        prompt_user_and_remediate(visible, skip_cache, seen_connections)
                    elif mode == "silent":
                        silent_remediate(visible)

                    for conn in visible:
                        seen_connections.add((conn['program'].lower(), conn['pid'], conn['port']))

            save_json_file(SKIP_CACHE_FILE, list(skip_cache))
            save_json_file(SEEN_CACHE_FILE, list(seen_connections))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user.")
        logger.info("Agent terminated by user.")
        save_json_file(SKIP_CACHE_FILE, list(skip_cache))
        save_json_file(SEEN_CACHE_FILE, list(seen_connections))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-Time PortMap AI Agent")
    parser.add_argument("--mode", choices=["prompt", "silent"], default="prompt", help="Choose between manual or automatic remediation")
    parser.add_argument("--interval", type=int, default=10, help="Scan interval in seconds")
    args = parser.parse_args()

    run_realtime_agent(args.mode, args.interval)
