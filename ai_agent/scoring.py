# ai_agent/scoring.py

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
    if seen is None:
        seen = set()
    if root is None:
        root = obj  # Remember the top-level object

    obj_id = id(obj)
    if obj_id in seen:
        return "<circular_ref>"

    seen.add(obj_id)

    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if v is root:
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

def log_connection(connection):
    try:
        if "behavior_flag" in connection:
            print("🔎 behavior_flag keys:", connection["behavior_flag"].keys())
            for k, v in connection["behavior_flag"].items():
                if v is connection:
                    print(f"🔁 Circular reference FOUND in key '{k}' of behavior_flag")

        # Fully sanitize without pre-serialization
        clean_conn = sanitize_for_logging(connection)
        print("🧪 Cleaned connection for logging:", clean_conn)

        # Use json.dump directly for better I/O handling
        with open(LOG_FILE, "a") as f:
            json.dump(clean_conn, f)
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
            connection['ml_flag'] = label
            connection['score'] = score
            log_connection(connection)
            return score
        except Exception as e:
            print(f"⚠️ ML scoring failed, falling back to stub: {e}")

    score = stub_score(connection)
    connection['score'] = score
    log_connection(connection)
    return score
