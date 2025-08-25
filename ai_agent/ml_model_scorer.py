# ai_agent/ml_model_scorer.py

import joblib
import numpy as np
from pathlib import Path

MODEL_PATH = Path.home() / ".portmap-ai" / "models" / "isolation_forest_model.pkl"
SUSPICIOUS_PROTOCOLS = {"SSH", "Telnet", "FTP", "IRC"}

class MLScorer:
    def __init__(self):
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"⚠️ Failed to load model: {e}")

    def is_loaded(self):
        return self.model is not None

    def extract_features(self, connection):
        return np.array([
            connection.get("port", 0),
            len(connection.get("payload", "")),
            connection.get("score", 0.5),
            connection.get("flags", "").count("S"),
            1 if connection.get("protocol") in SUSPICIOUS_PROTOCOLS else 0
        ]).reshape(1, -1)

    def predict(self, connection):
        if not self.model:
            raise RuntimeError("ML model not loaded.")

        features = self.extract_features(connection)
        label = self.model.predict(features)[0]   # -1 = anomaly, 1 = normal
        raw_score = self.model.decision_function(features)[0]
        status = "anomaly" if label == -1 else "normal"
        return status, round(raw_score, 3)

