# core_engine/modules/scanner.py

def basic_scan():
    print("⚠️ Running placeholder basic_scan() - returning dummy connections.")
    return [
        {"program": "dummy_app", "pid": 1234, "port": 8080, "payload": "GET /", "flags": "S", "protocol": "HTTP"},
        {"program": "dummy_db", "pid": 5678, "port": 3306, "payload": "SELECT * FROM users;", "flags": "", "protocol": "MySQL"}
    ]

