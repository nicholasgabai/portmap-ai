# anomaly_trainer.py

import os
import json
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest

# === Config ===
MODEL_DIR = Path.home() / ".portmap-ai" / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_FILE = MODEL_DIR / "isolation_forest_model.pkl"

# === Feature Extraction ===
suspicious_protocols = {"SSH", "Telnet", "FTP", "IRC"}

def extract_features(connection):
    return [
        connection.get("port", 0),
        len(connection.get("payload", "")),
        connection.get("score", 0.5),
        connection.get("flags", "").count("S"),
        1 if connection.get("protocol") in suspicious_protocols else 0
    ]

# === Training ===
def train_model(dataset):
    feature_vectors = [extract_features(conn) for conn in dataset]
    X = np.array(feature_vectors, dtype=np.float32)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_FILE)
    print(f"✅ Model trained and saved to {MODEL_FILE}")

# === Load Dataset from JSON ===
def load_training_data(json_file):
    with open(json_file, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train Isolation Forest model on network data")
    parser.add_argument("--input", required=True, help="Path to training data (JSON list of connections)")
    args = parser.parse_args()

    dataset = load_training_data(args.input)
    train_model(dataset)

