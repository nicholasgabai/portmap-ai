def classify_packet(connection):
    # Identify protocol from port
    known_ports = {
        22: "SSH", 23: "Telnet", 53: "DNS",
        80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        3389: "RDP", 4444: "Backdoor", 5555: "Malware", 31337: "Exploit"
    }
    port = int(connection.get("port", 0))
    connection["protocol"] = known_ports.get(port, "Unknown")

    # Simulate flagging
    connection["flagged"] = (
        connection["protocol"] == "Unknown" or
        connection.get("program", "").lower() in ["bad_actor", "malware_sim"]
    )

    return connection


def preprocess_batch(packet_batch):
    return [classify_packet(pkt) for pkt in packet_batch]

