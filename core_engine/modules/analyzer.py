from modules.protocol_labeler import label_protocols, guess_protocol_from_payload
from behavior_profiler import detect_behavioral_anomaly, update_profile

def deep_packet_inspect(connection):
    port = int(connection.get("port", 0))
    protocol = connection.get("protocol", "Unknown")
    flags = connection.get("flags", "")
    payload = connection.get("payload", "")

    expected_protocol = guess_protocol_from_payload(connection)
    if expected_protocol and expected_protocol != protocol:
        connection["dpi_flag"] = "unexpected_protocol"

    if isinstance(flags, str) and any(x in flags for x in ["S", "F"]) and "R" in flags:
        connection["dpi_flag"] = "suspicious_flag_combo"

    if isinstance(payload, str):
        if len(payload) > 1000:
            connection["dpi_flag"] = "large_payload"
        elif any(sig in payload.lower() for sig in ["cmd.exe", "/bin/sh", "curl", "wget", "powershell"]):
            connection["dpi_flag"] = "known_payload_signature"

    if "dpi_flag" not in connection:
        connection["dpi_flag"] = "clean"

    connection["dpi"] = connection["dpi_flag"]
    return connection

def analyze_connections(connections):
    labeled = label_protocols(connections)
    for conn in labeled:
        conn = deep_packet_inspect(conn)
        conn = detect_behavioral_anomaly(conn)
        update_profile(conn)
        conn["reason"] = conn.get("reason", f"Detected on port {conn['port']} with protocol {conn['protocol']}")
    return labeled

