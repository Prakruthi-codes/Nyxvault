import logging
import math
import networkx as nx
from typing import Dict, Any, List, Tuple

try:
    from services.neo4j_client import neo4j_client
except ModuleNotFoundError:
    from neo4j_client import neo4j_client

logger = logging.getLogger("nyxvault.attack_path")
logging.basicConfig(level=logging.INFO)

class AttackPathPredictor:
    def __init__(self):
        pass

    def build_probability_graph(self) -> Tuple[nx.DiGraph, List[Dict[str, Any]]]:
        """
        Queries Neo4j and constructs a directed NetworkX graph where edges
        have transition probabilities and costs mapped as -ln(probability).
        Returns the graph and a list of identified critical target assets.
        """
        G = nx.DiGraph()
        critical_assets = []

        # 1. Fetch nodes and mark critical assets
        # Customers
        customers = neo4j_client.execute_query("MATCH (c:Customer) RETURN c.id as id, c.name as name")
        for r in customers:
            G.add_node(r["id"], label="Customer", name=r["name"], is_critical=False)

        # Accounts (critical if honeytoken or balance > $250,000)
        accounts = neo4j_client.execute_query("MATCH (a:Account) RETURN a.id as id, a.account_type as name, a.balance as balance, a.is_honeytoken as is_honeytoken")
        for r in accounts:
            is_ht = bool(r.get("is_honeytoken", False))
            bal = float(r.get("balance") or 0.0)
            is_critical = is_ht or bal >= 250000.0
            
            G.add_node(r["id"], label="Account", name=r["name"], balance=bal, is_honeytoken=is_ht, is_critical=is_critical)
            if is_critical:
                critical_assets.append({
                    "id": r["id"],
                    "label": "Account",
                    "name": r["name"],
                    "reason": "Honeytoken Account" if is_ht else f"High-Value Account (${bal:,.2f})"
                })

        # APIs (critical if honeytoken)
        apis = neo4j_client.execute_query("MATCH (api:APIEndpoint) RETURN api.path as path, api.method as method, api.description as name, api.is_honeytoken as is_honeytoken")
        for r in apis:
            is_ht = bool(r.get("is_honeytoken", False))
            is_critical = is_ht
            
            G.add_node(r["path"], label="APIEndpoint", name=f"{r['method']} {r['path']}", is_honeytoken=is_ht, is_critical=is_critical)
            if is_critical:
                critical_assets.append({
                    "id": r["path"],
                    "label": "APIEndpoint",
                    "name": f"{r['method']} {r['path']}",
                    "reason": "Restricted Honeytoken API"
                })

        # Credentials (critical if honeytoken or role is admin)
        creds = neo4j_client.execute_query("MATCH (e:EmployeeCredential) RETURN e.username as username, e.role as name, e.is_honeytoken as is_honeytoken")
        for r in creds:
            is_ht = bool(r.get("is_honeytoken", False))
            role = r["name"] or "teller"
            is_critical = is_ht or role in ["treasury_admin", "reserve_controller"]
            
            G.add_node(r["username"], label="EmployeeCredential", name=f"{role} login", is_honeytoken=is_ht, is_critical=is_critical)
            if is_critical:
                critical_assets.append({
                    "id": r["username"],
                    "label": "EmployeeCredential",
                    "name": r["username"],
                    "reason": "Privileged Admin Credential" if not is_ht else "Honeytoken Login"
                })

        # Helper edge adder to map probability and cost
        def add_prob_edge(source: str, target: str, type_name: str, p: float):
            if G.has_node(source) and G.has_node(target):
                # cost = -ln(probability). A higher probability yields a lower cost.
                cost = -math.log(p)
                G.add_edge(source, target, type=type_name, probability=p, cost=cost)

        # 2. Map transition edges
        # HAS_CREDENTIAL = 0.90
        has_creds = neo4j_client.execute_query("MATCH (c:Customer)-[:HAS_CREDENTIAL]->(e:EmployeeCredential) RETURN c.id as source, e.username as target")
        for r in has_creds:
            add_prob_edge(r["source"], r["target"], "HAS_CREDENTIAL", 0.90)

        # OWNS = 0.95
        owns = neo4j_client.execute_query("MATCH (c:Customer)-[:OWNS]->(a:Account) RETURN c.id as source, a.id as target")
        for r in owns:
            add_prob_edge(r["source"], r["target"], "OWNS", 0.95)

        # ACCESSED = 0.80
        # If an IP/device has alert logs, it represents access patterns
        accessed = neo4j_client.execute_query("MATCH (a:Alert) RETURN a.source_ip as source, a.accessed_asset as target")
        for r in accessed:
            if r["source"] and r["target"]:
                if not G.has_node(r["source"]):
                    G.add_node(r["source"], label="IP", name="External IP", is_critical=False)
                add_prob_edge(r["source"], r["target"], "ACCESSED", 0.80)

        # TRANSFERRED_TO = dynamic weight based on transaction volume/count
        txs = neo4j_client.execute_query("""
        MATCH (a1:Account)-[r:TRANSFERRED_TO]->(a2:Account)
        RETURN a1.id as source, a2.id as target, avg(r.amount) as avg_amt, count(r) as tx_count
        """)
        for r in txs:
            # More frequent/larger transfers represent a higher probability of traversal
            # Cap dynamic probability between 0.40 and 0.85
            freq_factor = min(r["tx_count"] * 0.05, 0.20)
            amt_factor = min(r["avg_amt"] / 200000.0, 0.25)
            p = 0.40 + freq_factor + amt_factor
            add_prob_edge(r["source"], r["target"], "TRANSFERRED_TO", p)

        return G, critical_assets

    def predict_paths(self, source_id: str) -> Dict[str, Any]:
        """
        Runs a single-source Dijkstra shortest-path query over the transition cost graph.
        Identifies reachable assets, calculates overall probability/confidence, 
        and extracts the highest-risk (highest probability) path chain.
        """
        if not neo4j_client.verify_connectivity():
            logger.warning("Neo4j database offline. Skipping path prediction.")
            return {}

        G, critical_assets = self.build_probability_graph()

        if not G.has_node(source_id):
            logger.warning(f"Starting node {source_id} not found in transaction network.")
            return {
                "attack_probability": 0.0,
                "confidence": 0.0,
                "path_nodes": [],
                "reachable_assets_count": 0
            }

        # Dijkstra returns distances (costs) and paths to all reachable nodes
        try:
            costs, paths = nx.single_source_dijkstra(G, source=source_id, weight="cost")
        except Exception as e:
            logger.error(f"Single source Dijkstra computation failed: {e}")
            return {
                "attack_probability": 0.0,
                "confidence": 0.0,
                "path_nodes": [],
                "reachable_assets_count": 0
            }

        highest_prob = 0.0
        best_target = None
        best_path = []
        reachable_critical = []

        # Find the critical target node that has the highest cumulative probability (lowest cost)
        for target in critical_assets:
            target_id = target["id"]
            if target_id in costs and target_id != source_id:
                # Math conversion back to probability: P = e^(-cost)
                p = math.exp(-costs[target_id])
                
                reachable_critical.append({
                    "id": target_id,
                    "label": target["label"],
                    "name": target["name"],
                    "reason": target["reason"],
                    "probability": round(p * 100, 2)
                })

                if p > highest_prob:
                    highest_prob = p
                    best_target = target_id
                    best_path = paths[target_id]

        if not best_target:
            # No critical assets are reachable
            return {
                "attack_probability": 0.0,
                "confidence": 0.85,
                "path_nodes": [],
                "reachable_assets": [],
                "target_asset": None
            }

        # Format node details for UI consumption
        path_nodes_details = []
        for n_id in best_path:
            node_data = G.nodes[n_id]
            path_nodes_details.append({
                "id": n_id,
                "label": node_data.get("label", "Unknown"),
                "name": node_data.get("name", "Unknown")
            })

        # Confidence decays slightly based on length of path (longer paths introduce noise)
        path_length = len(best_path) - 1
        confidence = max(0.95 - (path_length * 0.05), 0.50)

        # Sort reachable critical assets by probability desc
        reachable_critical.sort(key=lambda x: x["probability"], reverse=True)

        return {
            "attack_probability": round(highest_prob * 100, 2), # Percentage representation
            "confidence": round(confidence, 2),
            "path_nodes": path_nodes_details,
            "target_asset": {
                "id": best_target,
                "label": G.nodes[best_target].get("label"),
                "name": G.nodes[best_target].get("name")
            },
            "reachable_assets": reachable_critical
        }

# Global predictor instance
attack_path_predictor = AttackPathPredictor()
