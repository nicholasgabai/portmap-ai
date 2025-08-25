# ai_agent/retrain_model.py

import json
from pathlib import Path
from anomaly_trainer import train_model, extract_features

LOG_FILE = Path.home() / ".portmap-ai" / "data" / "connection_log.jsonl"

def load_recent_data(n=1000):
    lines = []
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-n:]
    except Exception as e:
        print(f"⚠️ Failed to read training log: {e}")
    return [json.loads(line) for line in lines if line.strip()]

if __name__ == "__main__":
    data = load_recent_data()
    if not data:
        print("❌ No data to retrain on.")
    else:
        train_model(data)

