# ai_firewall.py (AI Firewall Main)

import sys
from pathlib import Path

# === Move sys.path update to the very top ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ✅ Now safe to import from ai_agent
import os
import json
import logging
import random
import argparse

from simulator import get_test_packet_batch
from inbound_monitor import inspect_inbound_payloads
from firewall_hooks import execute_firewall_action
from scapy.all import sniff, IP, TCP, UDP
from modules.protocol_labeler import label_protocols, guess_protocol_from_payload
from modules.dispatcher import process_packet_batch

BASE_DIR = Path.home() / ".portmap-ai"
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
SETTINGS_FILE = DATA_DIR / "settings.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ai_firewall")
logger.setLevel(logging.INFO)
log_path = LOG_DIR / "ai_firewall.log"
file_handler = logging.FileHandler(log_path)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

FIREWALL_SETTINGS = {}
if SETTINGS_FILE.exists():
    try:
        with open(SETTINGS_FILE) as f:
            FIREWALL_SETTINGS = json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load settings: {e}")

def summarize_flags(packet):
    flags = ""
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        return str(flags)
    return "-"

def extract_conn_from_packet(packet):
    if not packet.haslayer(IP):
        return None
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Unknown"
    sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
    dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0
    flags = summarize_flags(packet)

    return {
        "program": "live_capture",
        "pid": random.randint(1000, 9999),
        "port": dport,
        "protocol": proto,
        "direction": "incoming",
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "flags": flags
    }

def live_packet_callback(packet):
    conn = extract_conn_from_packet(packet)
    if conn:
        process_packet_batch([conn], logger, FIREWALL_SETTINGS.get("enable_autolearn", False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run AI-integrated firewall component")
    parser.add_argument("--mode", choices=["standalone", "masternode", "client"], default="standalone", help="Run mode for the firewall")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    parser.add_argument("--live", action="store_true", help="Enable live sniffing mode (requires sudo)")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        print("🔍 Debug mode is ON")

    print(f"🚦 Running in {args.mode.upper()} mode")
    logger.info(f"Started in {args.mode.upper()} mode")

    if args.live:
        print("📡 Live packet capture enabled (using scapy)")
        sniff(prn=live_packet_callback, store=0)
    else:
        test_data = get_test_packet_batch()
        process_packet_batch(test_data, logger, FIREWALL_SETTINGS.get("enable_autolearn", False))
