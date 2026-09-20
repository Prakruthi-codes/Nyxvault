import logging
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, List

try:
    from services.neo4j_client import neo4j_client
except ModuleNotFoundError:
    from neo4j_client import neo4j_client

logger = logging.getLogger("nyxvault.anomaly_detector")
logging.basicConfig(level=logging.INFO)

class AnomalyDetectionEngine:
    def __init__(self):
        # contamination represents expected ratio of anomalous accounts
        self.model = IsolationForest(contamination=0.06, random_state=42)

    def fetch_behavioral_features(self) -> pd.DataFrame:
        """
        Queries Neo4j and computes behavioral feature vectors for each Account.
        Features:
        - average_transaction_amount
        - transfers_per_day
        - unique_recipients
        - account_age (days)
        - login_frequency (sessions/month)
        - api_access_count
        """
        # Fetch standard metrics per account
        query = """
        MATCH (a:Account)
        OPTIONAL MATCH (a)-[out:TRANSFERRED_TO]->(dest)
        WITH a, 
             avg(out.amount) as avg_amt, 
             count(out) as total_txs, 
             count(distinct dest) as unique_dest
             
        OPTIONAL MATCH (c:Customer)-[:OWNS]->(a)
        OPTIONAL MATCH (c)-[:HAS_CREDENTIAL]->(e:EmployeeCredential)
        
        RETURN a.id as account_id, 
               coalesce(avg_amt, 0.0) as average_transaction_amount,
               coalesce(total_txs, 0.0) / 30.0 as transfers_per_day,
               coalesce(unique_dest, 0) as unique_recipients,
               coalesce(a.account_age, toInteger(rand() * 400 + 30)) as account_age,
               coalesce(e.login_frequency, toInteger(rand() * 20 + 2)) as login_frequency,
               coalesce(e.api_access_count, toInteger(rand() * 40 + 5)) as api_access_count
        """
        records = neo4j_client.execute_query(query)
        
        # Parse into pandas DataFrame
        df = pd.DataFrame(records)
        if df.empty:
            return pd.DataFrame(columns=[
                "account_id", "average_transaction_amount", "transfers_per_day",
                "unique_recipients", "account_age", "login_frequency", "api_access_count"
            ])
        return df

    def detect_anomalies(self) -> Dict[str, Any]:
        """
        Runs the Isolation Forest anomaly detection algorithm over the transaction metrics.
        Computes anomaly scores, flags anomalous nodes, and saves them back to Neo4j.
        """
        if not neo4j_client.verify_connectivity():
            logger.warning("Neo4j database offline. Skipping anomaly detection.")
            return {}

        df = self.fetch_behavioral_features()
        if df.empty or len(df) < 5:
            logger.warning("Not enough account records to train anomaly detector.")
            return {}

        logger.info(f"Analyzing {len(df)} accounts for behavioral anomalies...")
        
        # Prepare feature matrix (exclude ID column)
        feature_cols = [
            "average_transaction_amount", 
            "transfers_per_day", 
            "unique_recipients", 
            "account_age", 
            "login_frequency", 
            "api_access_count"
        ]
        X = df[feature_cols].values

        # Standardize features log-scale or simple fit
        # Fit Isolation Forest
        self.model.fit(X)
        
        # Predict outliers: -1 represents anomaly, 1 represents normal
        predictions = self.model.predict(X)
        
        # decision_function gives a raw float score (values closer to -0.5 are outliers, closer to +0.5 are inliers)
        decision_scores = self.model.decision_function(X)

        timestamp = datetime.now().isoformat()
        anom_count = 0

        # Update database properties
        for i, row in df.iterrows():
            acc_id = row["account_id"]
            is_anom = predictions[i] == -1
            
            # Map raw decision score into a [0.0, 1.0] anomaly score
            # Score mappings: decision_score <= 0.0 => score >= 0.50
            raw_score = (0.25 - decision_scores[i]) * 1.5
            anom_score = min(max(raw_score, 0.05), 1.0)
            anom_score = float(round(anom_score, 4))

            # Compose a concise natural language explanation
            reason = self._generate_anomaly_reason(row, is_anom, anom_score)
            
            # Update account node in Neo4j
            update_query = """
            MATCH (a:Account {id: $id})
            SET a.anomaly_score = $score,
                a.is_anomalous = $is_anomalous,
                a.anomaly_reason = $reason,
                a.last_analyzed_at = $timestamp
            """
            try:
                neo4j_client.execute_query(update_query, {
                    "id": acc_id,
                    "score": anom_score,
                    "is_anomalous": is_anom,
                    "reason": reason,
                    "timestamp": timestamp
                })
                if is_anom:
                    anom_count += 1
            except Exception as e:
                logger.error(f"Failed to save anomaly properties for account {acc_id}: {e}")

        logger.info(f"Anomaly detection complete. Identified {anom_count} anomalous accounts.")
        return {
            "total_analyzed": len(df),
            "anomalies_detected": anom_count,
            "timestamp": timestamp
        }

    def _generate_anomaly_reason(self, row: pd.Series, is_anom: bool, score: float) -> str:
        """Composes a logical explanation based on feature values relative to averages."""
        if not is_anom:
            return "Transaction behavior matches normal client patterns."
            
        reasons = []
        if row["average_transaction_amount"] > 100000:
            reasons.append(f"Average wire transfer amount (${row['average_transaction_amount']:,.2f}) is extremely high")
        if row["transfers_per_day"] > 5.0:
            reasons.append(f"Transfer rate ({row['transfers_per_day']:.2f}/day) is abnormally high")
        if row["unique_recipients"] > 15:
            reasons.append(f"Interacted with {row['unique_recipients']} unique recipients in 30 days")
        if row["api_access_count"] > 35:
            reasons.append("API traffic indicates automated polling or script behavior")
            
        if not reasons:
            reasons.append("Multi-factor transaction attributes deviate from standard account cluster profile")

        return f"Behavioral discrepancy: {'; '.join(reasons)}. Anomaly score: {score:.2f}."

# Global detector instance
anomaly_detector = AnomalyDetectionEngine()
