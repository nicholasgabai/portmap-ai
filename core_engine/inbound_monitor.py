import random

def inspect_inbound_response(packet):
    # Simulated payload signature check
    known_malicious_signatures = ["cmd.exe", "/bin/sh", "base64,", "powershell", "nc -lvp", "wget http", "curl -fsSL"]
    payload = packet.get("payload", "").lower()

    if any(sig in payload for sig in known_malicious_signatures):
        packet["inbound_flag"] = "malicious_payload"
    elif len(payload) > 1000:
        packet["inbound_flag"] = "suspicious_size"
    elif "ping" in payload or "whoami" in payload:
        packet["inbound_flag"] = "reconnaissance_behavior"
    else:
        packet["inbound_flag"] = "clean"

    return packet


def run_inbound_monitor(allowed_connections):
    flagged = []
    for pkt in allowed_connections:
        if pkt.get("decision") == "allow":
            pkt = inspect_inbound_response(pkt)
            if pkt["inbound_flag"] != "clean":
                flagged.append(pkt)
    return flagged


def inspect_inbound_payloads(connection):
    # Placeholder logic for future anomaly detection on payloads
    print(f"📥 Inbound anomaly inspection stub: {connection}")
    return []  # Ensure it returns an empty list for compatibility

