import json

def get_node_role(settings_path='core_engine/data/settings.json'):
    """
    Returns either 'master' or 'slave' based on config file.
    """
    try:
        with open(settings_path, 'r') as f:
            settings = json.load(f)
        return settings.get("node_role", "slave")  # default to slave
    except Exception as e:
        print(f"⚠️ Failed to load node role: {e}")
        return "slave"

