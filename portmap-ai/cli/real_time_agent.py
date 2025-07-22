import time
import requests
import argparse
import logging
import psutil
from remediator import remediate
from portmap_scan import scan_ports

# Setup logging
logger = logging.getLogger("realtime_agent")
logger.setLevel(logging.INFO)
handler = logging.FileHandler("/Users/Nico/portmap-ai/logs/realtime_agent.log")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

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

def prompt_user_and_remediate(flagged, skip_cache):
    apply_all = False
    i = 0
    total = len(flagged)

    while i < total:
        conn = flagged[i]
        normalized_reason = conn['reason'].split(" (")[0].strip()
        skip_key = (conn['program'].lower(), normalized_reason)

        if skip_key in skip_cache:
            i += 1
            continue

        print(f"\n⚠ Suspicious: {conn['program']} (PID {conn['pid']}, Port {conn['port']}) - Reason: {conn['reason']}")
        decision = input("Remediate? [y]es / [n]o / [a]ll / [s]kip all / [e]xit list: ").strip().lower()

        if decision == "y":
            remediate(conn)
            logger.info(f"Remediated PID {conn['pid']} ({conn['program']}) - Reason: {conn['reason']}")
        elif decision == "n":
            logger.info(f"Skipped PID {conn['pid']} ({conn['program']})")
            skip_cache.add(skip_key)
        elif decision == "a":
            logger.info("User selected apply to all.")
            for rem_conn in flagged[i:]:
                remediate(rem_conn)
                logger.info(f"Remediated PID {rem_conn['pid']} ({rem_conn['program']}) - Reason: {rem_conn['reason']}")
            return "all"
        elif decision == "s":
            print(f"✔ Skipped remaining {total - i} entries.")
            logger.info(f"User skipped remaining remediations from index {i}.")
            for rem_conn in flagged[i:]:
                norm_reason = rem_conn['reason'].split(" (")[0].strip()
                skip_cache.add((rem_conn['program'].lower(), norm_reason))
            return "skip"
        elif decision == "e":
            logger.info("User exited the list early.")
            print("📤 Exiting prompt mode, will check again in next cycle...")
            return "exit"
        else:
            print("Invalid input. Enter y, n, a, s, or e.")
            continue

        i += 1

def silent_remediate(flagged):
    for conn in flagged:
        logger.info(f"Auto-remediating: {conn}")
        remediate(conn)
        logger.info(f"Remediated PID {conn['pid']} ({conn['program']}) - Reason: {conn['reason']}")

def run_realtime_agent(mode, interval):
    print(f"🛰 Running PortMap AI Agent in {mode.upper()} mode with {interval}s interval...")
    logger.info(f"Started agent in {mode} mode")

    skip_cache = set()

    while True:
        results = scan_ports()
        ai_response = send_to_ai_agent(results)
        if ai_response and ai_response.get("recommendation") == "review":
            flagged = ai_response.get("flagged_connections", [])
            print(f"\n⚠️ Detected {len(flagged)} suspicious connections")
            logger.info(f"Flagged: {flagged}")
            if mode == "prompt":
                user_decision = prompt_user_and_remediate(flagged, skip_cache)
                if user_decision in ["skip", "exit"]:
                    time.sleep(interval)
                    continue
            elif mode == "silent":
                silent_remediate(flagged)
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-Time PortMap AI Agent")
    parser.add_argument("--mode", choices=["prompt", "silent"], default="prompt", help="Choose between manual or automatic remediation")
    parser.add_argument("--interval", type=int, default=10, help="Scan interval in seconds")
    args = parser.parse_args()

    run_realtime_agent(args.mode, args.interval)
