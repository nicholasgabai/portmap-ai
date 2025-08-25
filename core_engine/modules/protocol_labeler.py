PORT_PROTOCOL_MAP = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Backdoor",
    5555: "Malware",
    31337: "Exploit"
}

def guess_protocol_from_payload(connection):
    payload = connection.get("payload", "").upper()
    port = connection.get("port", 0)

    if payload.startswith("GET") or "HTTP/" in payload:
        return "HTTP"
    elif "mysql_native_password" in payload or port in [3306, 3307]:
        return "MySQL"
    elif "SSH-" in payload:
        return "SSH"
    elif "USER" in payload and "PASS" in payload:
        return "FTP"
    elif any(tool in payload for tool in ["cmd.exe", "/bin/sh", "powershell", "nc -lvp"]):
        return "Exploit"
    return "Unknown"



def label_protocols(connections):
    for conn in connections:
        port = int(conn.get("port", 0))
        payload = conn.get("payload", "")
        guessed = guess_protocol_from_payload(conn)
        default_label = PORT_PROTOCOL_MAP.get(port, "Unknown")
        conn["protocol"] = guessed if guessed != "Unknown" else default_label
    return connections

