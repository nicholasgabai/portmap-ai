# ai_agent/ml_data_logger.py

import json
from pathlib import Path
from datetime import datetime

LOG_FILE = Path.home() / ".portmap-ai" / "data" / "connection_log.jsonl"

def log_connection(connection):
    try:
        connection = connection.copy()
        connection["timestamp"] = datetime.utcnow().isoformat()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(connection) + "\n")
    except Exception as e:
        print(f"⚠️ Failed to log connection: {e}")

