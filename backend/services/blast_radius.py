import logging
import networkx as nx
from typing import Dict, Any, List

try:
    from services.attack_path import attack_path_predictor
except ModuleNotFoundError:
    from attack_path import attack_path_predictor

logger = logging.getLogger("nyxvault.blast_radius")
logging.basicConfig(level=logging.INFO)

class BlastRadiusEstimator:
    def __init__(self):
        pass

    def estimate_blast_radius(self, source_id: str) -> Dict[str, Any]:
        """
        Estimates the downstream damage if the given node_id is compromised:
        - Total financial exposure (sum of balances of reachable accounts).
        - Count of affected accounts.
        - Count of affected customers.
        - Count of reachable critical assets (honeytokens, wealth nodes, admin logins).
        """
        try:
            # Reuses the networkx probability graph build to ensure consistency
            G, _ = attack_path_predictor.build_probability_graph()
        except Exception as e:
            logger.error(f"Failed to build network graph for blast radius: {e}")
            return self._empty_response()

        if not G.has_node(source_id):
            logger.warning(f"Node {source_id} not found in blast radius network.")
            return self._empty_response()

        # Gather all descendants (any node reachable from the source node via directed edges)
        try:
            descendants = nx.descendants(G, source_id)
        except Exception as e:
            logger.error(f"Failed to compute descendants: {e}")
            return self._empty_response()

        # Include the source node itself in the blast radius calculations
        affected_nodes = list(descendants) + [source_id]

        financial_exposure = 0.0
        affected_accounts_count = 0
        affected_customers_count = 0
        critical_assets_count = 0
        critical_assets_list = []

        for node_id in affected_nodes:
            node_data = G.nodes[node_id]
            label = node_data.get("label", "Unknown")
            is_critical = node_data.get("is_critical", False)

            if label == "Account":
                affected_accounts_count += 1
                bal = float(node_data.get("balance") or 0.0)
                financial_exposure += bal
                
                if is_critical:
                    critical_assets_count += 1
                    critical_assets_list.append({
                        "id": node_id,
                        "label": "Account",
                        "name": node_data.get("name", "Account"),
                        "reason": "Honeytoken" if node_data.get("is_honeytoken") else "High-Value"
                    })

            elif label == "Customer":
                affected_customers_count += 1

            elif label == "APIEndpoint":
                if is_critical:
                    critical_assets_count += 1
                    critical_assets_list.append({
                        "id": node_id,
                        "label": "APIEndpoint",
                        "name": node_data.get("name", "API"),
                        "reason": "Honeytoken API"
                    })

            elif label == "EmployeeCredential":
                if is_critical:
                    critical_assets_count += 1
                    critical_assets_list.append({
                        "id": node_id,
                        "label": "EmployeeCredential",
                        "name": node_data.get("name", "Credential"),
                        "reason": "Privileged Admin" if not node_data.get("is_honeytoken") else "Honeytoken Login"
                    })

        # Format financial exposure into a human-readable string (e.g. ₹ or $ format)
        # Indian Rupee Lakh/Crore formatting style if required or standard Crore text
        crore_value = financial_exposure / 10000000.0  # 1 Crore = 10 Million (10,000,000)
        
        if crore_value >= 0.1:
            formatted_exposure = f"₹{crore_value:.2f} Crore"
        else:
            formatted_exposure = f"₹{financial_exposure/100000.0:.2f} Lakh"

        return {
            "source_id": source_id,
            "financial_exposure": round(financial_exposure, 2),
            "formatted_exposure": formatted_exposure,
            "affected_accounts": affected_accounts_count,
            "affected_customers": affected_customers_count,
            "critical_assets_count": critical_assets_count,
            "critical_assets": critical_assets_list
        }

    def _empty_response(self) -> Dict[str, Any]:
        return {
            "financial_exposure": 0.0,
            "formatted_exposure": "₹0.00 Lakh",
            "affected_accounts": 0,
            "affected_customers": 0,
            "critical_assets_count": 0,
            "critical_assets": []
        }

# Global estimator instance
blast_radius_estimator = BlastRadiusEstimator()
