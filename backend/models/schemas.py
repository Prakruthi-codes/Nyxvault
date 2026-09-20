from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

# --- Stats Schema ---
class SystemStats(BaseModel):
    total_customers: int
    total_accounts: int
    total_transactions: int
    active_threats: int
    mutation_count: int

# --- Cytoscape Graph Schema ---
class CytoscapeNodeData(BaseModel):
    id: str
    label: str
    type: str # Customer, Account, APIEndpoint, EmployeeCredential
    name: str
    risk_score: Optional[float] = None
    balance: Optional[float] = None
    is_honeytoken: bool = False
    details: Optional[Dict[str, Any]] = None

class CytoscapeNode(BaseModel):
    data: CytoscapeNodeData

class CytoscapeEdgeData(BaseModel):
    id: str
    source: str
    target: str
    type: str # OWNS, TRANSFERRED_TO, HAS_CREDENTIAL
    amount: Optional[float] = None
    timestamp: Optional[str] = None

class CytoscapeEdge(BaseModel):
    data: CytoscapeEdgeData

class CytoscapeGraph(BaseModel):
    nodes: List[CytoscapeNode]
    edges: List[CytoscapeEdge]

# --- Event Stream Schemas ---
class SecurityEvent(BaseModel):
    event_id: str
    event_type: str # "attack", "detection", "mutation"
    timestamp: str
    title: str
    description: str
    risk_score: float
    threat_type: Optional[str] = None
    confidence: Optional[float] = None
    source_ip: Optional[str] = None
    accessed_asset: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

# --- Simulation & Control Schemas ---
class SimulationTrigger(BaseModel):
    attack_type: str # "insider_threat", "credential_theft", "api_recon", "transaction_exploration"
    source_entity_id: Optional[str] = None

class SimulationStatusResponse(BaseModel):
    is_running: bool
    interval_seconds: int

class MutationStatusResponse(BaseModel):
    is_running: bool
    interval_minutes: int
    mutation_count: int
