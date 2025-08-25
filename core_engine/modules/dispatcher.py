# dispatcher.py

from modules.protocol_labeler import label_protocols
from inbound_monitor import inspect_inbound_payloads
from firewall_hooks import execute_firewall_action
from modules.risk_assessor import calculate_risk_score

def process_packet_batch(connections, logger=None, autolearn=False):
    labeled = label_protocols(connections)
    enriched = []
    for conn in labeled:
        calculate_risk_score(conn, logger, autolearn)
        enriched.append(conn)

    flagged = inspect_inbound_payloads(enriched)
    for conn in enriched:
        if conn in flagged:
            print(f"📥 Inbound anomaly inspection stub: {conn}")

        decision = decide(conn)
        conn["decision"] = decision
        execute_firewall_action(conn, decision)

def decide(conn):
    score = conn.get("score", 0)
    if score >= 0.75:
        return "block"
    elif score >= 0.45:
        return "review"
    return "allow"

