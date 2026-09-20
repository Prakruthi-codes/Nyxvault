const API_BASE = import.meta.env.VITE_API_URL 
  ? `${import.meta.env.VITE_API_URL}/api/v1`
  : "http://localhost:8000/api/v1";

export interface SystemStats {
  total_customers: number;
  total_accounts: number;
  total_transactions: number;
  active_threats: number;
  mutation_count: number;
  threat_score_distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  predicted_financial_exposure: number;
  formatted_exposure: string;
  fraud_rings_count: number;
  attack_probability_forecast: number;
  honeytoken_activations: number;
  blast_radius_summary: {
    avg_affected_accounts: number;
    avg_affected_customers: number;
  };
}

export interface CytoscapeNodeData {
  id: string;
  label: string;
  type: string;
  name: string;
  risk_score?: number;
  balance?: number;
  is_honeytoken: boolean;
  details?: Record<string, any>;
}

export interface CytoscapeNode {
  data: CytoscapeNodeData;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  type: string;
  amount?: number;
  timestamp?: string;
}

export interface CytoscapeEdge {
  data: CytoscapeEdgeData;
}

export interface CytoscapeGraph {
  nodes: CytoscapeNode[];
  edges: CytoscapeEdge[];
}

export interface SecurityEvent {
  event_id: string;
  event_type: "attack" | "detection" | "mutation";
  timestamp: string;
  title: string;
  description: string;
  risk_score: number;
  threat_type?: string;
  confidence?: number;
  source_ip?: string;
  accessed_asset?: string;
  details: Record<string, any>;
}

export interface FraudRing {
  ring_id: string;
  size: number;
  risk_score: number;
  exposure: number;
  formatted_exposure: string;
  account_ids: string[];
}

export interface BlastRadius {
  source_id: string;
  financial_exposure: number;
  formatted_exposure: string;
  affected_accounts: number;
  affected_customers: number;
  critical_assets_count: number;
  critical_assets: Array<{
    id: string;
    label: string;
    name: string;
    reason: string;
  }>;
}

export interface AttackPath {
  attack_probability: number;
  confidence: number;
  path_nodes: Array<{
    id: string;
    label: string;
    name: string;
  }>;
  target_asset?: {
    id: string;
    label: string;
    name: string;
  };
  reachable_assets: Array<{
    id: string;
    label: string;
    name: string;
    reason: string;
    probability: number;
  }>;
}

export interface EntityRiskReport {
  entity: {
    id: string;
    label: string;
    name: string;
    threat_score: number;
    risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    is_honeytoken: boolean;
    anomaly_score: number;
    is_anomalous: boolean;
    anomaly_reason?: string;
    fraud_ring_id?: string;
    fraud_ring_size?: number;
    fraud_ring_risk?: number;
  };
  attack_path: AttackPath;
  blast_radius: BlastRadius;
  ai_explanation: {
    explanation: string;
    confidence: number;
    recommended_action: string;
  };
}

export const apiService = {
  async getStats(): Promise<SystemStats> {
    const res = await fetch(`${API_BASE}/stats`);
    if (!res.ok) throw new Error("Failed to fetch system stats");
    return res.json();
  },

  async getGraphData(limit: number = 150): Promise<CytoscapeGraph> {
    const res = await fetch(`${API_BASE}/graph?limit_transactions=${limit}`);
    if (!res.ok) throw new Error("Failed to fetch cytoscape graph data");
    return res.json();
  },

  async getAttackPathGraph(sourceId: string): Promise<CytoscapeGraph> {
    const res = await fetch(`${API_BASE}/graph/attack-path?source_id=${encodeURIComponent(sourceId)}`);
    if (!res.ok) throw new Error("Failed to fetch attack path subgraph");
    return res.json();
  },

  async getEntityRiskReport(entityId: string): Promise<EntityRiskReport> {
    const res = await fetch(`${API_BASE}/risk/entity/${encodeURIComponent(entityId)}`);
    if (!res.ok) throw new Error("Failed to fetch entity risk report");
    return res.json();
  },

  async getBlastRadius(entityId: string): Promise<BlastRadius> {
    const res = await fetch(`${API_BASE}/blast-radius/${encodeURIComponent(entityId)}`);
    if (!res.ok) throw new Error("Failed to fetch blast radius profile");
    return res.json();
  },

  async getFraudRings(): Promise<{ rings_count: number; rings: FraudRing[] }> {
    const res = await fetch(`${API_BASE}/fraud-rings`);
    if (!res.ok) throw new Error("Failed to fetch fraud rings");
    return res.json();
  },

  async recalculateRiskIntelligence(): Promise<any> {
    const res = await fetch(`${API_BASE}/risk/recalculate`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to run risk intelligence recalculation");
    return res.json();
  },

  async getSimulationStatus(): Promise<{ is_running: boolean; interval_seconds: number }> {
    const res = await fetch(`${API_BASE}/simulation/status`);
    if (!res.ok) throw new Error("Failed to fetch simulation status");
    return res.json();
  },

  async startSimulation(): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/start`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to start simulation");
    return res.json();
  },

  async stopSimulation(): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/stop`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to stop simulation");
    return res.json();
  },

  async triggerSimulationScenario(type: "credential-theft" | "lateral-movement" | "fraud-ring"): Promise<any> {
    const res = await fetch(`${API_BASE}/simulation/${type}`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to queue simulation scenario");
    return res.json();
  },

  async getMutationStatus(): Promise<{ is_running: boolean; interval_minutes: number; mutation_count: number }> {
    const res = await fetch(`${API_BASE}/mutation/status`);
    if (!res.ok) throw new Error("Failed to fetch mutation status");
    return res.json();
  },

  async startMutation(): Promise<any> {
    const res = await fetch(`${API_BASE}/mutation/start`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to start mutation");
    return res.json();
  },

  async stopMutation(): Promise<any> {
    const res = await fetch(`${API_BASE}/mutation/stop`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to stop mutation");
    return res.json();
  },

  async triggerMutation(): Promise<any> {
    const res = await fetch(`${API_BASE}/mutation/trigger`, { method: "POST" });
    if (!res.ok) throw new Error("Failed to trigger immediate mutation");
    return res.json();
  },
};
