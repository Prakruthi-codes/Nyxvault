from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from services.neo4j_client import neo4j_client
from services.threat_scorer import threat_scorer
from services.anomaly_detector import anomaly_detector
from services.fraud_ring import fraud_detector
from services.attack_path import attack_path_predictor
from services.blast_radius import blast_radius_estimator
from services.explainer import ai_explainer
import logging

logger = logging.getLogger("nyxvault.api.risk")
router = APIRouter(tags=["Predictive Threat Risk Intelligence"])

@router.post("/risk/recalculate")
def trigger_intelligence_run():
    """
    Forces a complete intelligence scoring run:
    1. Runs Isolation Forest anomaly detection.
    2. Runs NetworkX Fraud Ring detection.
    3. Computes graph PageRank and degree centrality.
    4. Calculates and persists Threat Scores to Neo4j.
    """
    try:
        # Run in order
        anom_res = anomaly_detector.detect_anomalies()
        fraud_res = fraud_detector.detect_fraud_rings()
        score_res = threat_scorer.calculate_and_persist_scores()
        
        return {
            "status": "success",
            "message": "Intelligence run completed successfully.",
            "anomalies_metadata": anom_res,
            "fraud_rings_metadata": fraud_res,
            "threat_scoring_metadata": score_res
        }
    except Exception as e:
        logger.error(f"Intelligence scoring run failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Risk intelligence calculation failed: {str(e)}")

@router.get("/risk/entity/{entity_id}")
def get_entity_risk_report(entity_id: str):
    """
    Compiles a comprehensive risk intelligence report for a single node.
    Calculates dynamic attack paths, blast radius estimates, and generates
    explainable AI analyst reasoning.
    """
    if not neo4j_client.verify_connectivity():
        raise HTTPException(status_code=503, detail="Database connection offline")

    # 1. Fetch node basic parameters
    node_query = """
    MATCH (n)
    WHERE n.id = $id OR (n:APIEndpoint AND n.path = $id) OR (n:EmployeeCredential AND n.username = $id)
    RETURN labels(n)[0] as label,
           coalesce(n.id, n.path, n.username) as id,
           coalesce(n.name, n.description, n.role, n.path) as name,
           coalesce(n.threat_score, 0.0) as threat_score,
           coalesce(n.risk_level, 'LOW') as risk_level,
           coalesce(n.is_honeytoken, false) as is_honeytoken,
           coalesce(n.anomaly_score, 0.0) as anomaly_score,
           coalesce(n.is_anomalous, false) as is_anomalous,
           n.anomaly_reason as anomaly_reason,
           n.fraud_ring_id as fraud_ring_id,
           coalesce(n.fraud_ring_size, 0) as fraud_ring_size,
           coalesce(n.fraud_ring_risk, 0.0) as fraud_ring_risk
    """
    records = neo4j_client.execute_query(node_query, {"id": entity_id})
    if not records:
        raise HTTPException(status_code=404, detail=f"Entity '{entity_id}' not found in network graph")

    entity = records[0]

    # 2. Run graph traversals for attack paths and blast radius
    try:
        path = attack_path_predictor.predict_paths(entity_id)
        blast = blast_radius_estimator.estimate_blast_radius(entity_id)
    except Exception as e:
        logger.error(f"Failed to compile graph traversals for {entity_id}: {e}")
        path = {}
        blast = {}

    # Assemble payload for AI explainer
    entity_payload = {
        **entity,
        "attack_path": path,
        "blast_radius": blast
    }

    # 3. Generate AI Explanation
    try:
        explanation = ai_explainer.generate_explanation(entity_payload)
    except Exception as e:
        logger.error(f"AI explanation generation failed: {e}")
        explanation = {
            "explanation": "Failed to compile explanation context.",
            "confidence": 0.5,
            "recommended_action": "Manually verify transaction patterns."
        }

    return {
        "entity": entity,
        "attack_path": path,
        "blast_radius": blast,
        "ai_explanation": explanation
    }

@router.get("/blast-radius/{entity_id}")
def get_entity_blast_radius(entity_id: str):
    """Returns the blast radius profile for the given node."""
    return blast_radius_estimator.estimate_blast_radius(entity_id)

@router.get("/fraud-rings")
def get_detected_fraud_rings():
    """
    Returns a list of all detected circular laundering loops and communities
    containing accounts and transaction aggregates.
    """
    if not neo4j_client.verify_connectivity():
        raise HTTPException(status_code=503, detail="Database connection offline")

    # Group nodes by fraud_ring_id in Cypher
    query = """
    MATCH (a:Account)
    WHERE a.fraud_ring_id IS NOT NULL
    WITH a.fraud_ring_id as ring_id, 
         count(a) as size, 
         max(a.fraud_ring_risk) as risk,
         collect(a.id) as accounts,
         sum(a.balance) as total_bal
    RETURN ring_id, size, risk, accounts, total_bal
    ORDER BY risk DESC
    """
    records = neo4j_client.execute_query(query)
    
    rings = []
    for r in records:
        crore_val = r["total_bal"] / 10000000.0
        fmt_exposure = f"₹{crore_val:.2f} Crore" if crore_val >= 0.1 else f"₹{r['total_bal']/100000.0:.2f} Lakh"
        
        rings.append({
            "ring_id": r["ring_id"],
            "size": r["size"],
            "risk_score": r["risk"],
            "exposure": r["total_bal"],
            "formatted_exposure": fmt_exposure,
            "account_ids": r["accounts"]
        })

    return {
        "rings_count": len(rings),
        "rings": rings
    }
