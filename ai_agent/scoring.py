# ai_agent/scoring.py

import os
import random
from ai_agent.ml_model_scorer import MLScorer
from pathlib import Path
import json
import numpy as np

ml_scorer = MLScorer()

# === Logging Setup ===
LOG_FILE = Path.home() / ".portmap-ai" / "data" / "connection_log.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def sanitize_for_logging(obj, seen=None, root=None):
    """
    Recursively sanitize an object for safe JSON serialization.
    Handles circular references, NumPy data, and large payloads.
    """
    if seen is None:
        seen = set()
    if root is None:
        root = obj

    obj_id = id(obj)
    if obj_id in seen:
        return "<circular_ref>"
    seen.add(obj_id)

    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if k == "payload" and isinstance(v, str) and len(v) > 300:
                sanitized[k] = v[:300] + "..."
            elif v is root:
                sanitized[k] = "<circular_ref>"
            else:
                sanitized[k] = sanitize_for_logging(v, seen, root)
        return sanitized
    elif isinstance(obj, list):
        return [sanitize_for_logging(i, seen, root) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_for_logging(i, seen, root) for i in obj)
    elif isinstance(obj, np.generic):
        return float(obj)
    elif isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    else:
        return str(obj)

def log_connection(connection, file_path="logs/connection_log.jsonl"):
    try:
        # ✅ Ensure logs directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        clean_conn = sanitize_for_logging(connection)

        with open(file_path, "a") as f:
            f.write(json.dumps(clean_conn, indent=2))
            f.write("\n")

    except Exception as e:
        print(f"⚠️ Failed to log connection: {e}")
        import traceback
        traceback.print_exc()



# Load config to determine if ML should be used
def get_autolearn_setting():
    settings_path = Path.home() / ".portmap-ai" / "data" / "settings.json"
    try:
        if settings_path.exists():
            with open(settings_path, "r") as f:
                config = json.load(f)
                return config.get("enable_autolearn", False)
    except Exception as e:
        print(f"⚠️ Failed to read settings.json: {e}")
    return False

def stub_score(connection):
    """Return a dummy risk score between 0.2 and 0.95."""
    return round(random.uniform(0.2, 0.95), 3)

def get_score(connection, use_ml=None):
    """
    Get risk score for a given connection.

    If use_ml is True and the ML model is loaded, use it.
    If use_ml is None, it will load from config automatically.
    Otherwise fall back to random stub scoring.
    """
    if use_ml is None:
        use_ml = get_autolearn_setting()

    if use_ml and ml_scorer.is_loaded():
        try:
            label, score = ml_scorer.predict(connection)

            # 🧠 Inspect model outputs
            print(f"🧠 ML model returned: label={label} | score={score}")
            print(f"🧬 Type check: label={type(label)} | score={type(score)}")

            # ✅ Clean up potential circular label
            if isinstance(label, dict) and connection in label.values():
                print("⚠️ CIRCULAR label detected — fixing...")
                label = label.copy()
                label.pop("connection", None)

            # 🧼 Safe assignment
            if isinstance(label, (str, int, float)):
                connection['ml_flag'] = label
            else:
                connection['ml_flag'] = str(label)

            connection['score'] = score
            log_connection(connection)
            return score
        except Exception as e:
            print(f"⚠️ ML scoring failed, falling back to stub: {e}")

    score = stub_score(connection)
    connection['score'] = score
    log_connection(connection)
    return score

