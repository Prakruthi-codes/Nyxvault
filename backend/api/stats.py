from fastapi import APIRouter, HTTPException
from services.neo4j_client import neo4j_client
import logging
from typing import Dict, Any

logger = logging.getLogger("nyxvault.api.stats")
router = APIRouter(prefix="/stats", tags=["Statistics"])

@router.get("")
def get_executive_risk_stats():
    """
    Fetches aggregate business-risk threat intelligence metrics from Neo4j.
    """
    if not neo4j_client.verify_connectivity():
        raise HTTPException(status_code=503, detail="Database connection unavailable")

    try:
        # 1. Standard Counts
        cust_count = neo4j_client.execute_query("MATCH (c:Customer) RETURN count(c) as count")[0]["count"]
        acc_count = neo4j_client.execute_query("MATCH (a:Account) RETURN count(a) as count")[0]["count"]
        tx_count = neo4j_client.execute_query("MATCH ()-[r:TRANSFERRED_TO]->() RETURN count(r) as count")[0]["count"]
        
        # 2. Risk Distribution (LOW, MEDIUM, HIGH, CRITICAL)
        dist_query = """
        MATCH (n)
        WHERE n.risk_level IS NOT NULL
        RETURN n.risk_level as level, count(n) as count
        """
        dist_records = neo4j_client.execute_query(dist_query)
        distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in dist_records:
            level = r["level"]
            if level in distribution:
                distribution[level] += r["count"]

        # 3. Fraud Rings Count
        rings_query = "MATCH (a:Account) WHERE a.fraud_ring_id IS NOT NULL RETURN count(distinct a.fraud_ring_id) as count"
        rings_count = neo4j_client.execute_query(rings_query)[0]["count"]

        # 4. Honeytoken Trap Trigger Events
        traps_query = "MATCH (a:Alert) WHERE a.risk_score >= 90.0 RETURN count(a) as count"
        honeytoken_activations = neo4j_client.execute_query(traps_query)[0]["count"]

        # 5. Predicted Financial Exposure
        # Sum of balances of all accounts flagged as HIGH or CRITICAL risk (threat_score >= 61)
        exposure_query = "MATCH (a:Account) WHERE a.threat_score >= 61.0 RETURN sum(a.balance) as sum"
        exposure_res = neo4j_client.execute_query(exposure_query)
        exposure_val = float(exposure_res[0]["sum"] or 0.0)
        
        crore_val = exposure_val / 10000000.0
        formatted_exposure = f"₹{crore_val:.2f} Crore" if crore_val >= 0.1 else f"₹{exposure_val/100000.0:.2f} Lakh"

        # 6. Attack Probability Forecast (average threat score of High/Critical nodes)
        avg_risk_query = "MATCH (n) WHERE n.threat_score >= 61.0 RETURN avg(n.threat_score) as avg"
        avg_res = neo4j_client.execute_query(avg_risk_query)
        avg_risk = float(avg_res[0]["avg"] or 0.0)

        # 7. Blast Radius Summary (average affected accounts/customers per high risk node)
        # To avoid heavy traversing inside stats request, we fetch standard aggregates
        avg_blast_accs = 0.0
        avg_blast_custs = 0.0
        high_risk_nodes = neo4j_client.execute_query("MATCH (a:Account) WHERE a.threat_score >= 61.0 RETURN a.id as id LIMIT 5")
        if high_risk_nodes:
            # We estimate blast radius from a sample of 5 high risk nodes
            from services.blast_radius import blast_radius_estimator
            accs_sum = 0
            custs_sum = 0
            for node in high_risk_nodes:
                br = blast_radius_estimator.estimate_blast_radius(node["id"])
                accs_sum += br["affected_accounts"]
                custs_sum += br["affected_customers"]
            avg_blast_accs = round(accs_sum / len(high_risk_nodes), 1)
            avg_blast_custs = round(custs_sum / len(high_risk_nodes), 1)

        mutation_query = "MATCH (tracker:MutationTracker {id: 'global'}) RETURN tracker.mutation_count as count"
        mutation_res = neo4j_client.execute_query(mutation_query)
        mut_count = mutation_res[0]["count"] if (mutation_res and mutation_res[0]["count"] is not None) else 0

        return {
            "total_customers": cust_count,
            "total_accounts": acc_count,
            "total_transactions": tx_count,
            "active_threats": distribution["CRITICAL"] + distribution["HIGH"],
            "mutation_count": mut_count,
            "threat_score_distribution": distribution,
            "predicted_financial_exposure": exposure_val,
            "formatted_exposure": formatted_exposure,
            "fraud_rings_count": rings_count,
            "attack_probability_forecast": round(avg_risk, 2),
            "honeytoken_activations": honeytoken_activations,
            "blast_radius_summary": {
                "avg_affected_accounts": avg_blast_accs,
                "avg_affected_customers": avg_blast_custs
            }
        }
    except Exception as e:
        logger.error(f"Error retrieving executive statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Database aggregation failed: {str(e)}")
