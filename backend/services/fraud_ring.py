import logging
import uuid
import networkx as nx
from typing import Dict, Any, List, Set

try:
    from services.neo4j_client import neo4j_client
except ModuleNotFoundError:
    from neo4j_client import neo4j_client

logger = logging.getLogger("nyxvault.fraud_ring")
logging.basicConfig(level=logging.INFO)

class FraudRingDetector:
    def __init__(self):
        pass

    def fetch_transaction_network(self) -> nx.DiGraph:
        """
        Queries Neo4j for all Accounts and TRANSFERRED_TO relationships
        and returns a directed NetworkX graph.
        """
        G = nx.DiGraph()
        
        # Fetch Accounts
        acc_records = neo4j_client.execute_query("""
        MATCH (a:Account) 
        RETURN a.id as id, a.is_honeytoken as is_honeytoken, a.is_anomalous as is_anomalous
        """)
        for r in acc_records:
            G.add_node(
                r["id"], 
                is_honeytoken=bool(r.get("is_honeytoken", False)),
                is_anomalous=bool(r.get("is_anomalous", False))
            )

        # Fetch Transfers
        tx_records = neo4j_client.execute_query("""
        MATCH (a1:Account)-[r:TRANSFERRED_TO]->(a2:Account) 
        RETURN a1.id as source, a2.id as target, r.amount as amount
        """)
        for r in tx_records:
            source = r["source"]
            target = r["target"]
            # Ensure nodes exist
            if G.has_node(source) and G.has_node(target):
                if G.has_edge(source, target):
                    G[source][target]["weight"] += 1
                    G[source][target]["amount"] += r["amount"]
                else:
                    G.add_edge(source, target, weight=1, amount=r["amount"])

        return G

    def detect_fraud_rings(self) -> Dict[str, Any]:
        """
        Analyzes the transaction graph to detect strongly connected components,
        cycles, and communities. Saves identified fraud rings to Neo4j.
        """
        if not neo4j_client.verify_connectivity():
            logger.warning("Neo4j database offline. Skipping fraud ring detection.")
            return {}

        G = self.fetch_transaction_network()
        if len(G.nodes) == 0:
            logger.warning("Transaction network is empty. Skipping detection.")
            return {}

        # Reset existing fraud ring tags in DB before marking new ones
        neo4j_client.execute_query("""
        MATCH (a:Account) 
        REMOVE a.fraud_ring_id, a.fraud_ring_size, a.fraud_ring_risk
        """)
        logger.info("Cleared prior fraud ring variables in database.")

        detected_rings: List[Dict[str, Any]] = []
        ring_assignments: Dict[str, Dict[str, Any]] = {}
        ring_counter = 0

        # Method 1: Find Strongly Connected Components (SCC) of size >= 3
        # These represent tight loops where money can circulate.
        sccs = list(nx.strongly_connected_components(G))
        for scc in sccs:
            if len(scc) >= 3:
                ring_counter += 1
                ring_id = f"FR-SCC-{100 + ring_counter}"
                self._process_detected_ring(G, scc, ring_id, "Circular Laundering Loop", ring_assignments, detected_rings)

        # Method 2: Cycle Detection
        # Fallback to simple cycle finder inside dense components if SCC didn't catch them
        # Limit search depth to avoid combinatorial explosions
        try:
            # Look at cycles in the subgraph of remaining unassigned nodes
            unassigned_nodes = [node for node in G.nodes if node not in ring_assignments]
            subG = G.subgraph(unassigned_nodes)
            
            # Simple cycles returns list of nodes in a loop (directed)
            cycles = list(nx.simple_cycles(subG))
            # Sort cycles by length, take the longest loops first
            cycles = [c for c in cycles if len(c) >= 3]
            cycles.sort(key=len, reverse=True)
            
            # Select top non-overlapping cycles to avoid assigning one node to multiple rings
            assigned_cycle_nodes: Set[str] = set()
            for cycle in cycles:
                # Check overlap
                if not any(node in assigned_cycle_nodes for node in cycle):
                    ring_counter += 1
                    ring_id = f"FR-CYC-{200 + ring_counter}"
                    # Mark cycle nodes as assigned
                    for n in cycle:
                        assigned_cycle_nodes.add(n)
                    self._process_detected_ring(G, set(cycle), ring_id, "Circular Laundering Loop", ring_assignments, detected_rings)
        except Exception as e:
            logger.error(f"Cycle detection encountered error: {e}")

        # Method 3: Louvain/Greedy Modularity Community Detection
        # Connect communities that are highly dense and contain anomalous nodes
        try:
            # Modularity communities (requires undirected graph)
            undirG = G.to_undirected()
            communities = list(nx.community.greedy_modularity_communities(undirG))
            
            for comm in communities:
                if len(comm) >= 4:
                    # Check if this community contains anomalous nodes or has high risk
                    comm_nodes = list(comm)
                    anomalous_nodes = [n for n in comm_nodes if G.nodes[n].get("is_anomalous", False)]
                    
                    # If community contains anomalous nodes, flag it as a risk cluster
                    if len(anomalous_nodes) >= 2 and not any(node in ring_assignments for node in comm_nodes):
                        ring_counter += 1
                        ring_id = f"FR-COM-{300 + ring_counter}"
                        self._process_detected_ring(G, set(comm_nodes), ring_id, "High-Density Suspect Community", ring_assignments, detected_rings)
        except Exception as e:
            logger.error(f"Community modularity detection failed: {e}")

        # 3. Save findings to Neo4j
        for node_id, ring_info in ring_assignments.items():
            query = """
            MATCH (a:Account {id: $id})
            SET a.fraud_ring_id = $ring_id,
                a.fraud_ring_size = $size,
                a.fraud_ring_risk = $risk
            """
            try:
                neo4j_client.execute_query(query, {
                    "id": node_id,
                    "ring_id": ring_info["ring_id"],
                    "size": ring_info["size"],
                    "risk": ring_info["risk"]
                })
            except Exception as e:
                logger.error(f"Failed to tag fraud ring property for {node_id}: {e}")

        logger.info(f"Fraud ring detection finished. Flagged {len(detected_rings)} fraud rings.")
        return {
            "rings_detected_count": len(detected_rings),
            "rings": detected_rings
        }

    def _process_detected_ring(
        self, 
        G: nx.DiGraph, 
        nodes: Set[str], 
        ring_id: str, 
        ring_type: str, 
        assignments: Dict[str, Dict[str, Any]], 
        rings_list: List[Dict[str, Any]]
    ):
        """Calculates risk parameters for a detected set of nodes and maps them to assignments."""
        size = len(nodes)
        
        # Calculate Risk Score (0-100) based on anomalies, honeytokens, and transaction sizes
        anomaly_count = sum(1 for n in nodes if G.nodes[n].get("is_anomalous", False))
        contains_honeytoken = any(G.nodes[n].get("is_honeytoken", False) for n in nodes)
        
        # Calculate cumulative transaction amount inside the ring
        sub = G.subgraph(nodes)
        total_volume = sum(edge_data.get("amount", 0) for _, _, edge_data in sub.edges(data=True))

        # Risk formula
        base_risk = 40.0 + (anomaly_count / size) * 40.0
        if contains_honeytoken:
            base_risk += 20.0
        
        # Volume factor
        base_risk += min(total_volume / 500000.0, 10.0) # Up to 10 extra risk points for large laundering sums
        
        ring_risk = round(min(base_risk, 100.0), 2)

        # Append to summary report list
        rings_list.append({
            "ring_id": ring_id,
            "ring_type": ring_type,
            "size": size,
            "anomalous_accounts_count": anomaly_count,
            "total_internal_volume": total_volume,
            "risk_score": ring_risk,
            "node_ids": list(nodes)
        })

        # Map to assignments dictionary
        for node in nodes:
            assignments[node] = {
                "ring_id": ring_id,
                "size": size,
                "risk": ring_risk
            }

# Global detector instance
fraud_detector = FraudRingDetector()
