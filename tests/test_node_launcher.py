# tests/test_node_launcher.py
import os
import sys
import json
import argparse
import subprocess

# Add project root (portmap-ai/) to sys.path for any future imports
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def load_config(config_path):
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        sys.exit(1)

def launch_node(config_path, node_role):
    script = os.path.join("core_engine", f"{node_role}_node.py")
    if not os.path.exists(script):
        print(f"❌ Expected script {script} not found.")
        sys.exit(1)

    print(f"🚀 Launching {node_role.upper()} node with config: {config_path}")
    # Inherit current environment; run the Python module/script directly
    subprocess.run(["python3", script, "--config", config_path], check=False)

def main():
    parser = argparse.ArgumentParser(description="Portmap-ai Node Launcher")
    parser.add_argument("config", help="Path to the JSON config file")
    args = parser.parse_args()

    config = load_config(args.config)
    node_role = config.get("node_role", "").lower()

    if node_role not in ("master", "worker"):
        print("❌ Invalid or missing 'node_role' in config. Must be 'master' or 'worker'.")
        sys.exit(1)

    launch_node(args.config, node_role)

if __name__ == "__main__":
    main()
