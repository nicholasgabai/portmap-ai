import json
from pathlib import Path
from datetime import datetime

PROFILE_DB = Path.home() / ".portmap-ai" / "data" / "behavior_profile.json"

def load_profile():
    if PROFILE_DB.exists():
        try:
            with open(PROFILE_DB, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_profile(profile):
    with open(PROFILE_DB, "w") as f:
        json.dump(profile, f, indent=2)

def update_profile(connection):
    profile = load_profile()
    key = f"{connection['program']}:{connection['port']}"
    stats = profile.get(key, {"count": 0, "last_seen": None})
    stats["count"] += 1
    stats["last_seen"] = datetime.now().isoformat()
    profile[key] = stats
    save_profile(profile)

def detect_behavioral_anomaly(connection, autolearn=False):
    profile = load_profile()
    key = f"{connection['program']}:{connection['port']}"
    stats = profile.get(key)

    # NEVER include connection inside behavior_flag
    if not stats:
        behavior_flag = {"label": "new_behavior"}
    elif stats["count"] < 3:
        behavior_flag = {"label": "rare_behavior"}
    else:
        behavior_flag = {"label": "normal"}

    # Just in case: forcibly drop any accidental circular refs
    behavior_flag.pop("connection", None)
    

    connection["behavior_flag"] = behavior_flag
    return connection
