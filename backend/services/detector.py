import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple
from models.schemas import SecurityEvent
from datetime import datetime
import uuid

logger = logging.getLogger("nyxvault.detector")
logging.basicConfig(level=logging.INFO)

class ThreatDetectionEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self._initialize_and_train()

    def _initialize_and_train(self):
        """
        Generates standard baseline data representing 'normal' user behavior in the bank,
        and fits the Isolation Forest model.
        Features:
        1. Access Frequency (counts/minute): Normal is 1 to 5 accesses
        2. Amount Ratio (transaction amount / avg balance): Normal is 0.001 to 0.05
        3. Access Unauthorized Flag (0 for normal/clear, 1 for unauthorized role)
        """
        logger.info("Training Isolation Forest baseline model...")
        
        # Generate 1000 normal data points
        np.random.seed(42)
        n_samples = 1000
        
        freq = np.random.poisson(lam=2, size=n_samples) + 1 # normal low frequency
        amount_ratio = np.random.exponential(scale=0.01, size=n_samples) # normal small transactions
        unauthorized = np.random.choice([0, 1], size=n_samples, p=[0.98, 0.02]) # rare role mismatch

        # Construct dataframe
        train_data = np.column_stack((freq, amount_ratio, unauthorized))
        self.model.fit(train_data)
        logger.info("Isolation Forest threat detection model trained successfully.")

    def analyze_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        """
        Evaluates a raw access/simulation event and returns a processed SecurityEvent.
        Handles Honeytoken rule-based bypass + Isolation Forest anomaly detection.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        is_honeytoken = event_data.get("is_honeytoken", False)
        accessed_asset = event_data.get("accessed_asset", "unknown_asset")
        asset_type = event_data.get("asset_type", "unknown_type")
        username = event_data.get("username", "anonymous")
        
        # Extract features for scoring
        freq = event_data.get("access_frequency", 1.0)
        amount = event_data.get("amount", 0.0)
        avg_balance = event_data.get("avg_balance", 10000.0)
        amount_ratio = amount / avg_balance if avg_balance > 0 else 0.0
        unauthorized = 1 if event_data.get("unauthorized", False) else 0

        # Create details dictionary
        details = {
            "username": username,
            "accessed_asset": accessed_asset,
            "asset_type": asset_type,
            "access_frequency": freq,
            "amount": amount,
            "unauthorized": bool(unauthorized),
            "is_honeytoken": is_honeytoken
        }

        # 1. Rule-Based Bypass for Honeytokens (Features 2 & 4 Requirement)
        if is_honeytoken:
            risk_score = round(random_honeytoken_score(), 2)
            confidence = 1.0
            
            # Map threat type based on asset type
            if asset_type == "APIEndpoint":
                threat_type = "API Reconnaissance"
                title = "Critical: Honeytoken API Endpoint Accessed"
                desc = f"Compromised client or attacker accessed the fake endpoint '{accessed_asset}'."
            elif asset_type == "EmployeeCredential":
                threat_type = "Credential Theft"
                title = "Critical: Honeytoken Credentials Used"
                desc = f"An attempt was made to authenticate using fake credential '{username}'."
            else: # Account
                threat_type = "Insider Threat"
                title = "Critical: Honeytoken Account Accessed"
                desc = f"Unauthorized access to cognitive honeytoken account '{accessed_asset}'."

            return SecurityEvent(
                event_id=event_id,
                event_type="detection",
                timestamp=timestamp,
                title=title,
                description=desc,
                risk_score=risk_score,
                threat_type=threat_type,
                confidence=confidence,
                source_ip=event_data.get("source_ip", "10.0.12.84"),
                accessed_asset=accessed_asset,
                details=details
            )

        # 2. Machine Learning Anomaly Detection (Isolation Forest)
        feature_vector = np.array([[freq, amount_ratio, unauthorized]])
        
        # decision_function output: values < 0 are anomalies (the more negative, the more anomalous)
        # Typically values are between -0.5 and 0.5.
        decision_score = self.model.decision_function(feature_vector)[0]
        
        # Map decision score to risk score (0 to 100)
        # Normalized score where decision_score = 0.2 is low risk, and -0.2 is high risk.
        # Simple mapping:
        raw_risk = (0.3 - decision_score) * 125 # Map -0.2 to ~62.5, -0.4 to ~87.5
        risk_score = min(max(raw_risk, 5.0), 99.0) # Cap between 5% and 99%
        risk_score = round(risk_score, 2)

        # Classification label and confidence based on ML prediction
        is_anomaly = self.model.predict(feature_vector)[0] == -1
        
        if is_anomaly or risk_score > 70.0:
            confidence = round(min(max(abs(decision_score) * 2.0, 0.60), 0.98), 2)
            
            # Determine threat type based on triggers
            if unauthorized:
                threat_type = "Insider Threat"
                title = "Warning: High-Risk Access Pattern"
                desc = f"Employee '{username}' attempted access to unauthorized account '{accessed_asset}'."
            elif freq > 10:
                threat_type = "API Reconnaissance"
                title = "Warning: API Access Anomaly"
                desc = f"High frequency API access detected from username '{username}' on '{accessed_asset}'."
            else:
                threat_type = "Transaction Exploration"
                title = "Warning: Outlier Transaction Attempt"
                desc = f"Suspicious transaction of ${amount:,} attempted on account '{accessed_asset}'."
        else:
            threat_type = None
            confidence = round(min(max(1.0 - decision_score, 0.50), 0.85), 2)
            title = "Info: Standard User Interaction"
            desc = f"Normal interaction by client '{username}' on '{accessed_asset}'."

        return SecurityEvent(
            event_id=event_id,
            event_type="detection",
            timestamp=timestamp,
            title=title,
            description=desc,
            risk_score=risk_score,
            threat_type=threat_type,
            confidence=confidence,
            source_ip=event_data.get("source_ip", "10.0.12.84"),
            accessed_asset=accessed_asset,
            details=details
        )

def random_honeytoken_score() -> float:
    # Honeytoken scores are always high-risk (90 - 100)
    import random
    return random.uniform(90.0, 100.0)

# Global detection engine instance
detection_engine = ThreatDetectionEngine()
