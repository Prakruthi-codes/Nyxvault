import logging
import networkx as nx
from datetime import datetime
from typing import Dict, Any, List

try:
    from services.neo4j_client import neo4j_client
except ModuleNotFoundError:
    from neo4j_client import neo4j_client

logger = logging.getLogger("nyxvault.threat_scorer")
logging.basicConfig(level=logging.INFO)

class ThreatScoringEngine:
    def __init__(self):
        pass

    def build_networkx_graph(self) -> nx.DiGraph:
        """
        Fetches all nodes and relationships from Neo4j and compiles them
        into an in-memory NetworkX directed graph.
        """
        G = nx.DiGraph()
        
        # 1. Fetch Customers
        cust_records = neo4j_client.execute_query("MATCH (c:Customer) RETURN c.id as id")
        for r in cust_records:
            G.add_node(r["id"], label="Customer")

        # 2. Fetch Accounts
        acc_records = neo4j_client.execute_query("MATCH (a:Account) RETURN a.id as id, a.is_honeytoken as is_honeytoken")
        for r in acc_records:
            G.add_node(r["id"], label="Account", is_honeytoken=bool(r.get("is_honeytoken", False)))

        # 3. Fetch APIs
        api_records = neo4j_client.execute_query("MATCH (api:APIEndpoint) RETURN api.path as path, api.is_honeytoken as is_honeytoken")
        for r in api_records:
            G.add_node(r["path"], label="APIEndpoint", is_honeytoken=bool(r.get("is_honeytoken", False)))

        # 4. Fetch Credentials
        cred_records = neo4j_client.execute_query("MATCH (e:EmployeeCredential) RETURN e.username as username, e.is_honeytoken as is_honeytoken")
        for r in cred_records:
            G.add_node(r["username"], label="EmployeeCredential", is_honeytoken=bool(r.get("is_honeytoken", False)))

        # 5. Fetch OWNS Edges
        owns_records = neo4j_client.execute_query("MATCH (c:Customer)-[:OWNS]->(a:Account) RETURN c.id as source, a.id as target")
        for r in owns_records:
            G.add_edge(r["source"], r["target"], type="OWNS", weight=0.95)

        # 6. Fetch HAS_CREDENTIAL Edges
        has_cred_records = neo4j_client.execute_query("MATCH (c:Customer)-[:HAS_CREDENTIAL]->(e:EmployeeCredential) RETURN c.id as source, e.username as target")
        for r in has_cred_records:
            G.add_edge(r["source"], r["target"], type="HAS_CREDENTIAL", weight=0.90)

        # 7. Fetch TRANSFERRED_TO Edges
        tx_records = neo4j_client.execute_query("MATCH (a1:Account)-[r:TRANSFERRED_TO]->(a2:Account) RETURN a1.id as source, a2.id as target, r.amount as amount")
        for r in tx_records:
            # Multi-edges collapse in DiGraph, so we take maximum amount or cumulative weight
            weight = 0.5 + min(r.get("amount", 0) / 10000.0, 0.4)  # weight cap at 0.90
            G.add_edge(r["source"], r["target"], type="TRANSFERRED_TO", weight=weight)

        # 8. Fetch alerts/access logs that represent direct interactions
        alert_records = neo4j_client.execute_query("MATCH (a:Alert) RETURN a.source_ip as ip, a.accessed_asset as asset, a.risk_score as score")
        for r in alert_records:
            if r["asset"] and G.has_node(r["asset"]):
                # Link source IP or user (if available) to the asset
                source = r["ip"] or "compromised_device"
                if not G.has_node(source):
                    G.add_node(source, label="IPAddress")
                G.add_edge(source, r["asset"], type="ACCESSED", weight=0.80)

        return G

    def calculate_and_persist_scores(self) -> Dict[str, Any]:
        """
        Builds the graph, calculates PageRank and Degree Centrality, combines behavioral
        factors, computes threat scores, categorizes risk levels, and updates Neo4j.
        """
        if not neo4j_client.verify_connectivity():
            logger.warning("Neo4j database offline. Skipping threat score updates.")
            return {}

        logger.info("Recalculating network threat intelligence scores...")
        G = self.build_networkx_graph()
        
        if len(G.nodes) == 0:
            logger.warning("Graph contains no nodes. Skipping scoring.")
            return {}

        # 1. Compute NetworkX Graph Metrics
        try:
            pagerank = nx.pagerank(G, alpha=0.85, weight="weight")
        except Exception as e:
            logger.warning(f"PageRank computation failed (using fallback degree): {e}")
            pagerank = {node: 0.0 for node in G.nodes}

        degree_centrality = nx.degree_centrality(G)

        # Find max PageRank/Degree Centrality for normalization
        max_pr = max(pagerank.values()) if pagerank.values() else 1.0
        max_deg = max(degree_centrality.values()) if degree_centrality.values() else 1.0
        if max_pr == 0: max_pr = 1.0
        if max_deg == 0: max_deg = 1.0

        # Fetch extra metrics from Neo4j (anomaly flags, fraud rings, privilege levels)
        node_metadata = self._fetch_node_metadata()
        
        timestamp = datetime.now().isoformat()
        scored_count = 0
        risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        # 2. Iterate and score each node
        for node_id, data in G.nodes(data=True):
            label = data.get("label", "Unknown")
            is_ht = data.get("is_honeytoken", False)

            # Normalization (0-30 for PageRank, 0-20 for Degree Centrality)
            pr_factor = (pagerank[node_id] / max_pr) * 30.0
            deg_factor = (degree_centrality[node_id] / max_deg) * 20.0
            
            base_score = pr_factor + deg_factor

            # Retrieve database specific threat metrics
            meta = node_metadata.get(node_id, {})
            
            # Anomaly modifier
            is_anomalous = meta.get("is_anomalous", False)
            anomaly_score = meta.get("anomaly_score", 0.0)
            if is_anomalous:
                base_score += 25.0
            else:
                base_score += (anomaly_score * 20.0)

            # Privilege levels for Credentials
            role = meta.get("role", "none")
            if label == "EmployeeCredential":
                if role in ["treasury_admin", "reserve_controller"]:
                    base_score += 45.0
                elif role in ["teller", "compliance_analyst"]:
                    base_score += 15.0
                else:
                    base_score += 10.0

            # Fraud ring membership
            in_fraud_ring = meta.get("fraud_ring_id") is not None
            if in_fraud_ring:
                base_score += 35.0

            # Proximity to honeytokens
            near_honeytoken = self._check_honeytoken_proximity(G, node_id)
            if near_honeytoken:
                base_score += 30.0

            # Cap the standard score at 90 before Honeytoken interaction rules
            final_score = min(base_score, 90.0)

            # Rule-Based Honeytoken Escalation (Instant 95-100)
            if is_ht:
                final_score = 98.0
            
            # Check if this node has directly triggered any honeytoken alarms
            has_triggered_trap = meta.get("honeytoken_triggered", False)
            if has_triggered_trap:
                final_score = 99.5

            final_score = round(min(max(final_score, 5.0), 100.0), 2)

            # Classify Risk Level
            if final_score >= 81.0:
                risk_level = "CRITICAL"
            elif final_score >= 61.0:
                risk_level = "HIGH"
            elif final_score >= 31.0:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            risk_distribution[risk_level] += 1

            # 3. Persist back to Neo4j node properties based on label type
            self._write_score_to_db(node_id, label, final_score, risk_level, timestamp)
            scored_count += 1

        logger.info(f"Finished scoring {scored_count} entities. Risk Distribution: {risk_distribution}")
        return {
            "scored_count": scored_count,
            "distribution": risk_distribution,
            "timestamp": timestamp
        }

    # --- Database & Helper Queries ---
    def _fetch_node_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Retrieves specific details (anomalies, roles, fraud rings, alerts)
        from all database nodes to combine in scoring.
        """
        metadata = {}

        # Fetch anomalies (accounts and customers)
        anoms = neo4j_client.execute_query("""
        MATCH (n) 
        WHERE n:Account OR n:Customer
        RETURN n.id as id, n.is_anomalous as is_anomalous, n.anomaly_score as anomaly_score, n.fraud_ring_id as fraud_ring_id
        """)
        for r in anoms:
            metadata[r["id"]] = {
                "is_anomalous": bool(r.get("is_anomalous", False)),
                "anomaly_score": float(r.get("anomaly_score") or 0.0),
                "fraud_ring_id": r.get("fraud_ring_id")
            }

        # Fetch employee roles
        creds = neo4j_client.execute_query("""
        MATCH (e:EmployeeCredential) 
        RETURN e.username as username, e.role as role, e.fraud_ring_id as fraud_ring_id
        """)
        for r in creds:
            metadata[r["username"]] = {
                "role": r["role"],
                "fraud_ring_id": r.get("fraud_ring_id")
            }

        # Fetch honeytoken trigger history
        # If an entity is associated with a critical alert, it has triggered a honeytoken trap
        alerts = neo4j_client.execute_query("""
        MATCH (a:Alert) 
        WHERE a.risk_score >= 90.0
        RETURN a.accessed_asset as asset, a.source_ip as ip
        """)
        for r in alerts:
            # Mark the accessed asset and IP as honeytoken triggers
            if r["asset"]:
                if r["asset"] not in metadata: metadata[r["asset"]] = {}
                metadata[r["asset"]]["honeytoken_triggered"] = True

        return metadata

    def _check_honeytoken_proximity(self, G: nx.DiGraph, node_id: str) -> bool:
        """Checks if a node is adjacent to any honeytoken node in the graph."""
        if not G.has_node(node_id):
            return False
        
        for neighbor in G.neighbors(node_id):
            if G.nodes[neighbor].get("is_honeytoken", False):
                return True
        return False

    def _write_score_to_db(self, node_id: str, label: str, score: float, level: str, timestamp: str):
        """Writes the computed scores back to the node properties in Neo4j."""
        query = ""
        if label == "Customer":
            query = """
            MATCH (n:Customer {id: $id}) 
            SET n.threat_score = $score, n.risk_level = $level, n.last_scored_at = $timestamp
            """
        elif label == "Account":
            query = """
            MATCH (n:Account {id: $id}) 
            SET n.threat_score = $score, n.risk_level = $level, n.last_scored_at = $timestamp
            """
        elif label == "APIEndpoint":
            query = """
            MATCH (n:APIEndpoint {path: $id}) 
            SET n.threat_score = $score, n.risk_level = $level, n.last_scored_at = $timestamp
            """
        elif label == "EmployeeCredential":
            query = """
            MATCH (n:EmployeeCredential {username: $id}) 
            SET n.threat_score = $score, n.risk_level = $level, n.last_scored_at = $timestamp
            """
        else:
            return

        try:
            neo4j_client.execute_query(query, {
                "id": node_id,
                "score": score,
                "level": level,
                "timestamp": timestamp
            })
        except Exception as e:
            logger.error(f"Failed to save score for node {node_id} ({label}): {e}")

# Global scorer instance
threat_scorer = ThreatScoringEngine()
