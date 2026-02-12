import joblib
import pandas as pd
import os
from typing import List, Dict, Union
from .models import Alert, LogEntry
from datetime import datetime

# Paths
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ai_models', 'threat_model.pkl')
ENCODERS_PATH = os.path.join(os.path.dirname(__file__), 'ai_models', 'encoders.pkl')

class AIDetector:
    def __init__(self):
        self.model = None
        self.encoders = None
        self.load_model()

    def load_model(self):
        """Loads the trained model and encoders."""
        if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.encoders = joblib.load(ENCODERS_PATH)
                print("AI Model loaded successfully.")
            except Exception as e:
                print(f"Error loading AI model: {e}")
        else:
            print("AI Model not found. AI detection will be disabled.")

    def _preprocess_entry(self, entry: Dict) -> pd.DataFrame:
        """Converts a log entry (dict) into a DataFrame row matching training features."""
        # Features: ['proto', 'service', 'conn_state', 'duration', 'orig_bytes', 'resp_bytes']
        # Note: We need to match the feature set used in training exactly.
        # Training used: proto, service, conn_state, duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts
        
        # Default values for missing fields
        data = {
            'proto': entry.get('proto', 'unknown'),
            'service': entry.get('service', 'other'),
            'conn_state': entry.get('conn_state', 'OTH'),
            'duration': float(entry.get('duration', 0)),
            'orig_bytes': float(entry.get('orig_bytes', 0)),
            'resp_bytes': float(entry.get('resp_bytes', 0)),
            'orig_pkts': float(entry.get('orig_pkts', 0)),
            'resp_pkts': float(entry.get('resp_pkts', 0))
        }
        
        df = pd.DataFrame([data])
        
        # Encode categorical
        if self.encoders:
            for col, le in self.encoders.items():
                if col in df.columns:
                    # Handle unseen labels by assigning a default (e.g., first class) or special encoding
                    # For simplicity/robustness, we use a helper to map safely
                    df[col] = df[col].apply(lambda x: self._safe_transform(le, x))
                    
        return df

    def _safe_transform(self, le, value):
        """Transform a label, handling unseen values."""
        try:
            return le.transform([str(value)])[0]
        except ValueError:
            # If unseen, result to the first class (usually 0) or a specific 'unknown' class if trained
            return 0 

    def detect_anomalies(self, logs: List[Union[LogEntry, Dict]]) -> List[Alert]:
        """
        Scans logs for malicious intent using the ML model.
        Returns a list of Alerts.
        """
        if not self.model:
            return []

        alerts = []
        for log in logs:
            # Normalize to dict if it's a LogEntry
            log_data = log.__dict__ if hasattr(log, '__dict__') else log
            
            # Prepare input
            X_input = self._preprocess_entry(log_data)
            
            # Predict
            try:
                prediction = self.model.predict(X_input)[0]
                
                # Logic: Prediction is the 'detailed-label'.
                # In training: '-' was mapped to 'Benign'.
                # So anything NOT 'Benign' is an anomaly.
                
                if prediction != 'Benign':
                    # Create Alert
                    alert = Alert(
                        timestamp=log_data.get('timestamp', datetime.now()),
                        src_ip=log_data.get('src_ip') or log_data.get('id.orig_h', 'unknown'),
                        severity="Medium", # ML isn't perfect, keep it Medium
                        alert_type=f"AI Detection: {prediction}",
                        description=f"Machine Learning model classified flow as {prediction}",
                        mitre_id="T1071" # Application Layer Protocol (C&C)
                    )
                    alerts.append(alert)
                    
            except Exception as e:
                # print(f"Prediction error: {e}") # Reduce noise
                pass
                
        return alerts

# Singleton instance
ai_detector = AIDetector()

def detect_ml_anomalies(logs: List[Union[LogEntry, Dict]]) -> List[Alert]:
    """Wrapper function to be detected by main pipeline."""
    return ai_detector.detect_anomalies(logs)
