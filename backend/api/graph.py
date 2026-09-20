from fastapi import APIRouter, HTTPException, Query
from services.neo4j_client import neo4j_client
from services.attack_path import attack_path_predictor
from models.schemas import CytoscapeGraph, CytoscapeNode, CytoscapeNodeData, CytoscapeEdge, CytoscapeEdgeData
import logging
from typing import List

logger = logging.getLogger("nyxvault.api.graph")
router = APIRouter(prefix="/graph", tags=["Graph Explorer"])

@router.get("", response_model=CytoscapeGraph)
def get_graph_data(
    limit_transactions: int = Query(default=150, ge=10, le=1000),
    include_credentials: bool = Query(default=True),
    include_apis: bool = Query(default=True)
):
    """
    Queries Neo4j and returns graph elements including threat score,
    risk levels, and fraud ring IDs for visualization.
    """
    if not neo4j_client.verify_connectivity():
        raise HTTPException(status_code=503, detail="Database connection unavailable")

    try:
        nodes = []
        edges = []
        node_ids = set()

        # 1. Fetch Customers
        cust_query = """
        MATCH (c:Customer) 
        RETURN c.id as id, c.name as name, 
               coalesce(c.threat_score, 10.0) as threat_score, 
               coalesce(c.risk_level, 'LOW') as risk_level, 
               c.customer_type as type,
               c.fraud_ring_id as fraud_ring_id
        """
        cust_records = neo4j_client.execute_query(cust_query)
        for r in cust_records:
            nodes.append(CytoscapeNode(data=CytoscapeNodeData(
                id=r["id"],
                label="Customer",
                type="Customer",
                name=r["name"],
                risk_score=r["threat_score"],
                is_honeytoken=False,
                details={
                    "customer_type": r["type"],
                    "risk_level": r["risk_level"],
                    "fraud_ring_id": r.get("fraud_ring_id")
                }
            )))
            node_ids.add(r["id"])

        # 2. Fetch Accounts
        acc_query = """
        MATCH (a:Account) 
        RETURN a.id as id, a.account_type as name, a.balance as balance, 
               coalesce(a.is_honeytoken, false) as is_honeytoken,
               coalesce(a.threat_score, 10.0) as threat_score, 
               coalesce(a.risk_level, 'LOW') as risk_level,
               a.fraud_ring_id as fraud_ring_id
        """
        acc_records = neo4j_client.execute_query(acc_query)
        for r in acc_records:
            nodes.append(CytoscapeNode(data=CytoscapeNodeData(
                id=r["id"],
                label="Account",
                type="Account",
                name=r["name"],
                balance=r["balance"],
                is_honeytoken=bool(r["is_honeytoken"]),
                risk_score=r["threat_score"],
                details={
                    "account_type": r["name"],
                    "risk_level": r["risk_level"],
                    "fraud_ring_id": r.get("fraud_ring_id")
                }
            )))
            node_ids.add(r["id"])

        # 3. Fetch APIs
        if include_apis:
            api_query = """
            MATCH (api:APIEndpoint) 
            RETURN api.path as path, api.method as method, api.description as desc, 
                   coalesce(api.is_honeytoken, false) as is_honeytoken,
                   coalesce(api.threat_score, 10.0) as threat_score, 
                   coalesce(api.risk_level, 'LOW') as risk_level,
                   api.fraud_ring_id as fraud_ring_id
            """
            api_records = neo4j_client.execute_query(api_query)
            for r in api_records:
                nodes.append(CytoscapeNode(data=CytoscapeNodeData(
                    id=r["path"],
                    label="APIEndpoint",
                    type="APIEndpoint",
                    name=f"{r['method']} {r['path']}",
                    is_honeytoken=bool(r["is_honeytoken"]),
                    risk_score=r["threat_score"],
                    details={
                        "method": r["method"],
                        "description": r["desc"],
                        "risk_level": r["risk_level"],
                        "fraud_ring_id": r.get("fraud_ring_id")
                    }
                )))
                node_ids.add(r["path"])

        # 4. Fetch Credentials
        if include_credentials:
            cred_query = """
            MATCH (e:EmployeeCredential) 
            RETURN e.username as username, e.role as role, e.employee_id as emp_id, 
                   coalesce(e.is_honeytoken, false) as is_honeytoken,
                   coalesce(e.threat_score, 10.0) as threat_score, 
                   coalesce(e.risk_level, 'LOW') as risk_level,
                   e.fraud_ring_id as fraud_ring_id
            """
            cred_records = neo4j_client.execute_query(cred_query)
            for r in cred_records:
                nodes.append(CytoscapeNode(data=CytoscapeNodeData(
                    id=r["username"],
                    label="EmployeeCredential",
                    type="EmployeeCredential",
                    name=r["username"],
                    is_honeytoken=bool(r["is_honeytoken"]),
                    risk_score=r["threat_score"],
                    details={
                        "role": r["role"],
                        "employee_id": r["emp_id"],
                        "risk_level": r["risk_level"],
                        "fraud_ring_id": r.get("fraud_ring_id")
                    }
                )))
                node_ids.add(r["username"])

        # 5. Fetch OWNS Relationships
        owns_records = neo4j_client.execute_query("MATCH (c:Customer)-[:OWNS]->(a:Account) RETURN c.id as source, a.id as target")
        for r in owns_records:
            if r["source"] in node_ids and r["target"] in node_ids:
                edges.append(CytoscapeEdge(data=CytoscapeEdgeData(
                    id=f"owns-{r['source']}-{r['target']}",
                    source=r["source"],
                    target=r["target"],
                    type="OWNS"
                )))

        # 6. Fetch HAS_CREDENTIAL Relationships
        if include_credentials:
            cred_rel_records = neo4j_client.execute_query("MATCH (c:Customer)-[:HAS_CREDENTIAL]->(e:EmployeeCredential) RETURN c.id as source, e.username as target")
            for r in cred_rel_records:
                if r["source"] in node_ids and r["target"] in node_ids:
                    edges.append(CytoscapeEdge(data=CytoscapeEdgeData(
                        id=f"hascred-{r['source']}-{r['target']}",
                        source=r["source"],
                        target=r["target"],
                        type="HAS_CREDENTIAL"
                    )))

        # 7. Fetch TRANSFERRED_TO Relationships
        tx_query = """
        MATCH (a1:Account)-[r:TRANSFERRED_TO]->(a2:Account)
        RETURN a1.id as source, a2.id as target, r.amount as amount, r.timestamp as timestamp
        ORDER BY r.timestamp DESC
        LIMIT $limit
        """
        tx_records = neo4j_client.execute_query(tx_query, {"limit": limit_transactions})
        for i, r in enumerate(tx_records):
            if r["source"] in node_ids and r["target"] in node_ids:
                edges.append(CytoscapeEdge(data=CytoscapeEdgeData(
                    id=f"tx-{r['source']}-{r['target']}-{i}",
                    source=r["source"],
                    target=r["target"],
                    type="TRANSFERRED_TO",
                    amount=r["amount"],
                    timestamp=r["timestamp"]
                )))

        return CytoscapeGraph(nodes=nodes, edges=edges)
    except Exception as e:
        logger.error(f"Error compiling cytoscape graph: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to compile graph schema: {str(e)}")

@router.get("/attack-path", response_model=CytoscapeGraph)
def get_attack_path_graph(source_id: str):
    """
    Returns a CytoscapeGraph representing the predicted attack propagation path
    from the given compromised starting node to its highest risk target.
    """
    if not neo4j_client.verify_connectivity():
        raise HTTPException(status_code=503, detail="Database connection unavailable")

    try:
        # Run Dijkstra traversal to get best path nodes
        path_res = attack_path_predictor.predict_paths(source_id)
        path_nodes = path_res.get("path_nodes", [])
        
        if not path_nodes:
            return CytoscapeGraph(nodes=[], edges=[])

        # Convert path nodes list into Cytoscape nodes
        nodes = []
        node_ids = set()
        for idx, node in enumerate(path_nodes):
            n_id = node["id"]
            # Fetch node details from Neo4j
            detail_query = """
            MATCH (n) 
            WHERE n.id = $id OR (n:APIEndpoint AND n.path = $id) OR (n:EmployeeCredential AND n.username = $id)
            RETURN labels(n)[0] as label,
                   coalesce(n.is_honeytoken, false) as is_honeytoken,
                   coalesce(n.threat_score, 10.0) as threat_score
            """
            recs = neo4j_client.execute_query(detail_query, {"id": n_id})
            is_ht = False
            score = 10.0
            if recs:
                is_ht = bool(recs[0]["is_honeytoken"])
                score = float(recs[0]["threat_score"])

            nodes.append(CytoscapeNode(data=CytoscapeNodeData(
                id=n_id,
                label=node["label"],
                type=node["label"],
                name=node["name"],
                is_honeytoken=is_ht,
                risk_score=score
            )))
            node_ids.add(n_id)

        # Build predicted transition edges connecting the path
        edges = []
        for i in range(len(path_nodes) - 1):
            source = path_nodes[i]["id"]
            target = path_nodes[i + 1]["id"]
            
            # Query relationship type between these two in Neo4j
            rel_query = """
            MATCH (n1)-[r]->(n2)
            WHERE (n1.id = $s OR (n1:APIEndpoint AND n1.path = $s) OR (n1:EmployeeCredential AND n1.username = $s))
              AND (n2.id = $t OR (n2:APIEndpoint AND n2.path = $t) OR (n2:EmployeeCredential AND n2.username = $t))
            RETURN type(r) as type
            LIMIT 1
            """
            recs = neo4j_client.execute_query(rel_query, {"s": source, "t": target})
            rel_type = recs[0]["type"] if recs else "PREDICTED_PROPAGATION"

            edges.append(CytoscapeEdge(data=CytoscapeEdgeData(
                id=f"path-edge-{source}-{target}",
                source=source,
                target=target,
                type=rel_type
            )))

        return CytoscapeGraph(nodes=nodes, edges=edges)
    except Exception as e:
        logger.error(f"Error compiling attack path graph: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to compile path subgraph: {str(e)}")
