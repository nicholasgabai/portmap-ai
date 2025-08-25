from flask import Flask, request, jsonify

app = Flask(__name__)

# AI decision logic
def analyze(scan_data):
    flagged = []
    known_safe_programs = {"python", "mysqld", "remoted", "ControlCenter", "rapportd", "Google Chrome", "Google Chrome Helper"}
    known_malicious_ports = {4444, 5555, 31337}  # Common backdoor/malware ports
    suspicious_outbound_threshold = 10
    outbound_counter = {}

    for entry in scan_data:
        try:
            port = int(entry.get("port", 0))
        except:
            port = 0

        program = entry.get("program", "").lower()
        direction = entry.get("direction", "").lower()
        status = entry.get("status", "").lower()

        # 1. High port, unknown program
        if port > 40000 and not any(keyword in program for keyword in ("vpn", "proxy", "python")):
            flagged.append({
                "port": entry["port"],
                "pid": entry["pid"],
                "program": entry["program"],
                "reason": "High port used by unknown program"
            })

        # 2. Sensitive ports by unknown process
        if port in (22, 23, 3389) and "remote" not in program and program not in known_safe_programs:
            flagged.append({
                "port": entry["port"],
                "pid": entry["pid"],
                "program": entry["program"],
                "reason": "Sensitive port used by unrecognized process"
            })

        # 3. Malware-associated ports
        if port in known_malicious_ports:
            flagged.append({
                "port": entry["port"],
                "pid": entry["pid"],
                "program": entry["program"],
                "reason": "Common backdoor/malware port detected"
            })

        # 4. Too many outbound connections from one program
        if direction == "outgoing":
            outbound_counter[program] = outbound_counter.get(program, 0) + 1

    for program, count in outbound_counter.items():
        if count > suspicious_outbound_threshold:
            flagged.append({
                "port": "-",
                "pid": "-",
                "program": program,
                "reason": f"Program has excessive outbound connections ({count})"
            })

    recommendation = "review" if flagged else "clean"
    return {
        "flagged_connections": flagged,
        "recommendation": recommendation
    }


# Flask route handler
@app.route("/analyze", methods=["POST"])
def analyze_scan():
    data = request.get_json()

    print("\n📥 Received request on /analyze")
    print("🔍 Raw data received:", data)

    if not data:
        print("❌ No data received!")
        return jsonify({"error": "No scan data provided"}), 400

    result = analyze(data)

    print("✅ AI Response:", result)

    return jsonify(result)


if __name__ == "__main__":
    app.run(port=5050)
