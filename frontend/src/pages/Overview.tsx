import React, { useState, useEffect } from "react";
import { type SystemStats, type CytoscapeGraph, type EntityRiskReport, apiService } from "../services/api";
import { 
  Play, Bomb, RefreshCw, Loader, 
  TrendingUp, HelpCircle, AlertCircle, ArrowRight, UserCheck, Key, Code2, AlertTriangle
} from "lucide-react";

interface OverviewProps {
  stats: SystemStats;
  onRefresh: () => void;
}

export default function Overview({
  stats,
  onRefresh,
}: OverviewProps) {
  // Simulator triggers
  const [triggeringSim, setTriggeringSim] = useState<string | null>(null);
  const [triggeringMut, setTriggeringMut] = useState(false);
  const [recalculatingRisk, setRecalculatingRisk] = useState(false);
  
  // High Risk Entities & Dropdowns State
  const [graphData, setGraphData] = useState<CytoscapeGraph | null>(null);
  const [loadingGraph, setLoadingGraph] = useState(true);

  // What-If Simulator State
  const [selectedEntityId, setSelectedEntityId] = useState("");
  const [simulatingWhatIf, setSimulatingWhatIf] = useState(false);
  const [whatIfReport, setWhatIfReport] = useState<EntityRiskReport | null>(null);

  // Fetch graph data on load to populate dropdowns and Top Risk Entities
  const fetchGraphData = async () => {
    setLoadingGraph(true);
    try {
      const data = await apiService.getGraphData(200);
      setGraphData(data);
      if (data.nodes.length > 0) {
        // Default select first credential or node
        const firstCred = data.nodes.find(n => n.data.type === "EmployeeCredential") || data.nodes[0];
        setSelectedEntityId(firstCred.data.id);
      }
    } catch (e) {
      console.error("Failed to load graph data for simulator mapping:", e);
    } finally {
      setLoadingGraph(false);
    }
  };

  useEffect(() => {
    fetchGraphData();
  }, [stats.mutation_count]); // Reload dropdowns when mutations run

  const handleRecalculateRisk = async () => {
    setRecalculatingRisk(true);
    try {
      await apiService.recalculateRiskIntelligence();
      onRefresh();
      await fetchGraphData();
    } catch (e) {
      console.error(e);
    } finally {
      setRecalculatingRisk(false);
    }
  };

  const triggerScenario = async (type: "credential-theft" | "lateral-movement" | "fraud-ring") => {
    setTriggeringSim(type);
    try {
      await apiService.triggerSimulationScenario(type);
      // Wait a moment for simulation events to process in DB
      setTimeout(() => {
        handleRecalculateRisk();
      }, 1500);
    } catch (e) {
      console.error(e);
    } finally {
      setTriggeringSim(null);
    }
  };

  const triggerMutation = async () => {
    setTriggeringMut(true);
    try {
      await apiService.triggerMutation();
    } catch (e) {
      console.error(e);
    } finally {
      setTimeout(() => {
        setTriggeringMut(false);
        onRefresh();
        fetchGraphData();
      }, 1500);
    }
  };

  const runWhatIfSimulation = async () => {
    if (!selectedEntityId) return;
    setSimulatingWhatIf(true);
    setWhatIfReport(null);
    try {
      const report = await apiService.getEntityRiskReport(selectedEntityId);
      setWhatIfReport(report);
    } catch (e) {
      console.error(e);
    } finally {
      setSimulatingWhatIf(false);
    }
  };

  // Extract top high risk entities from graphData
  const getTopHighRiskEntities = () => {
    if (!graphData) return [];
    return [...graphData.nodes]
      .filter(n => n.data.risk_score !== undefined)
      .sort((a, b) => (b.data.risk_score || 0) - (a.data.risk_score || 0))
      .slice(0, 5);
  };

  const topEntities = getTopHighRiskEntities();

  // Distribution chart helper
  const dist = stats.threat_score_distribution || { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const totalDistribution = (dist.LOW + dist.MEDIUM + dist.HIGH + dist.CRITICAL) || 1;

  const getEntityIcon = (type: string) => {
    switch (type) {
      case "EmployeeCredential": return <Key className="h-3.5 w-3.5 text-yellow-500" />;
      case "APIEndpoint": return <Code2 className="h-3.5 w-3.5 text-purple-500" />;
      default: return <UserCheck className="h-3.5 w-3.5 text-cyan-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-slate-900 pb-4 space-y-3 sm:space-y-0">
        <div>
          <h2 className="text-xl font-bold text-slate-100 uppercase tracking-wider font-mono">EXECUTIVE THREAT INTELLIGENCE CENTER</h2>
          <p className="text-xs text-slate-500">Business risk modeling, predictive attack paths, and blast radius estimation.</p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={handleRecalculateRisk}
            disabled={recalculatingRisk}
            className="px-4 py-2 border border-cyber-accent hover:bg-cyber-accent/10 text-cyber-accent rounded font-mono text-xs font-semibold flex items-center space-x-2 transition-all"
          >
            {recalculatingRisk ? (
              <Loader className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            <span>RUN RISK AUDITING</span>
          </button>
          <button
            onClick={() => { onRefresh(); fetchGraphData(); }}
            className="px-4 py-2 border border-slate-800 hover:border-slate-700 text-slate-300 bg-slate-900 rounded font-mono text-xs font-semibold flex items-center space-x-2 transition-all"
          >
            <span>REFRESH</span>
          </button>
        </div>
      </div>

      {/* EXECUTIVE RISK WIDGETS */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Exposure */}
        <div className="p-5 rounded-lg border border-red-900/50 bg-red-950/10 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Predicted Financial Exposure</span>
            <p className="text-2xl font-bold font-mono tracking-tight text-red-400 glow-text-red">
              {stats.formatted_exposure || "₹0.00 Lakh"}
            </p>
          </div>
          <TrendingUp className="h-8 w-8 text-red-500 animate-pulse" />
        </div>

        {/* Attack Probability Forecast */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Avg Vulnerability Level</span>
            <p className="text-2xl font-bold font-mono tracking-tight text-slate-100">
              {stats.attack_probability_forecast || 0}%
            </p>
          </div>
          <AlertCircle className="h-8 w-8 text-amber-500" />
        </div>

        {/* Fraud Rings Detected */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Fraud Rings Detected</span>
            <p className="text-2xl font-bold font-mono tracking-tight text-slate-100">
              {stats.fraud_rings_count || 0}
            </p>
          </div>
          <AlertTriangle className="h-8 w-8 text-yellow-500 animate-pulse" />
        </div>

        {/* Honeytoken Activations */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Honeytoken Activations</span>
            <p className="text-2xl font-bold font-mono tracking-tight text-slate-100">
              {stats.honeytoken_activations || 0}
            </p>
          </div>
          <Bomb className="h-8 w-8 text-purple-500 animate-bounce" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* THREAT DISTRIBUTION CHART */}
        <div className="p-6 bg-slate-950 border border-slate-900 rounded-lg space-y-4">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-900 pb-2">
            Threat Score Distribution
          </h3>
          
          <div className="space-y-3.5 font-mono text-[11px]">
            {/* Critical */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-red-500 font-bold">
                <span>CRITICAL (81-100)</span>
                <span>{dist.CRITICAL} ({Math.round(dist.CRITICAL / totalDistribution * 100)}%)</span>
              </div>
              <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-red-500" style={{ width: `${dist.CRITICAL / totalDistribution * 100}%` }}></div>
              </div>
            </div>

            {/* High */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-orange-500 font-bold">
                <span>HIGH (61-80)</span>
                <span>{dist.HIGH} ({Math.round(dist.HIGH / totalDistribution * 100)}%)</span>
              </div>
              <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-orange-500" style={{ width: `${dist.HIGH / totalDistribution * 100}%` }}></div>
              </div>
            </div>

            {/* Medium */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-yellow-500 font-bold">
                <span>MEDIUM (31-60)</span>
                <span>{dist.MEDIUM} ({Math.round(dist.MEDIUM / totalDistribution * 100)}%)</span>
              </div>
              <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-yellow-500" style={{ width: `${dist.MEDIUM / totalDistribution * 100}%` }}></div>
              </div>
            </div>

            {/* Low */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-cyan-500 font-bold">
                <span>LOW (0-30)</span>
                <span>{dist.LOW} ({Math.round(dist.LOW / totalDistribution * 100)}%)</span>
              </div>
              <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-500" style={{ width: `${dist.LOW / totalDistribution * 100}%` }}></div>
              </div>
            </div>
          </div>
        </div>

        {/* TOP HIGH-RISK ENTITIES */}
        <div className="p-6 bg-slate-950 border border-slate-900 rounded-lg space-y-4">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-900 pb-2">
            Top High-Risk Entities
          </h3>
          
          <div className="space-y-2.5 overflow-y-auto max-h-[180px]">
            {loadingGraph ? (
              <div className="h-20 flex items-center justify-center text-xs text-slate-600 font-mono">LOADING RISKY ENTITIES...</div>
            ) : topEntities.length === 0 ? (
              <div className="h-20 flex items-center justify-center text-xs text-slate-600 font-mono">No High-Risk Entities. Run Scoring.</div>
            ) : (
              topEntities.map((e) => (
                <div key={e.data.id} className="p-2 border border-slate-900 bg-slate-900/10 rounded flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2.5 truncate">
                    {getEntityIcon(e.data.type)}
                    <span className="font-bold text-slate-300 truncate" title={e.data.name}>
                      {e.data.name}
                    </span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                    e.data.risk_score && e.data.risk_score >= 81 ? "bg-red-950 text-red-400" : "bg-orange-950 text-orange-400"
                  }`}>
                    {e.data.risk_score}%
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* DECISION SYSTEM SIMULATOR DRIVERS */}
        <div className="p-6 bg-slate-950 border border-slate-900 rounded-lg space-y-4">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-900 pb-2">
            Simulation Control Panel
          </h3>
          
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <button
              onClick={() => triggerScenario("credential-theft")}
              disabled={triggeringSim !== null}
              className="p-3 border border-slate-800 bg-slate-900/20 hover:bg-slate-900/40 rounded text-left text-slate-300 space-y-1.5 flex flex-col justify-between"
            >
              <span className="font-bold text-[10px] text-slate-400">CREDENTIAL THEFT</span>
              <span className="text-[8px] text-slate-500">Injects compromised privileged login usage</span>
            </button>

            <button
              onClick={() => triggerScenario("lateral-movement")}
              disabled={triggeringSim !== null}
              className="p-3 border border-slate-800 bg-slate-900/20 hover:bg-slate-900/40 rounded text-left text-slate-300 space-y-1.5 flex flex-col justify-between"
            >
              <span className="font-bold text-[10px] text-slate-400">LATERAL MOVEMENT</span>
              <span className="text-[8px] text-slate-500">Injects multi-hop routing traversal logs</span>
            </button>

            <button
              onClick={() => triggerScenario("fraud-ring")}
              disabled={triggeringSim !== null}
              className="p-3 border border-slate-800 bg-slate-900/20 hover:bg-slate-900/40 rounded text-left text-slate-300 space-y-1.5 flex flex-col justify-between"
            >
              <span className="font-bold text-[10px] text-slate-400">FRAUD RING CHAIN</span>
              <span className="text-[8px] text-slate-500">Creates strongly connected circular loops</span>
            </button>

            <button
              onClick={triggerMutation}
              disabled={triggeringMut}
              className="p-3 border border-slate-800 bg-slate-900/20 hover:bg-slate-900/40 rounded text-left text-slate-300 space-y-1.5 flex flex-col justify-between"
            >
              <span className="font-bold text-[10px] text-amber-500">MUTATE DECEPTION</span>
              <span className="text-[8px] text-slate-500">Force adapt decoy accounts & API endpoints</span>
            </button>
          </div>
        </div>
      </div>

      {/* WHAT-IF PREDICTIVE COMPROMISE SIMULATOR */}
      <div className="p-6 bg-slate-950 border border-slate-900 rounded-lg space-y-5">
        <div className="border-b border-slate-900 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2 font-mono">
            <HelpCircle className="h-4.5 w-4.5 text-cyber-accent" />
            <span>What-If Attack Path Simulator</span>
          </h3>
          <p className="text-[10px] text-slate-500 mt-1">Select any network node to predict vulnerability propagation, estimated loss, and impacted entities before compromise occurs.</p>
        </div>

        <div className="flex flex-col lg:flex-row gap-6">
          {/* CONTROL DROPDOWN */}
          <div className="lg:w-1/3 space-y-4">
            <div className="space-y-1.5">
              <label className="text-[10px] text-slate-400 font-bold uppercase font-mono">Select Starting Node:</label>
              {loadingGraph ? (
                <div className="h-10 border border-slate-900 rounded bg-slate-900/20 flex items-center justify-center text-[10px] text-slate-600 font-mono">LOADING SELECTABLES...</div>
              ) : (
                <select
                  value={selectedEntityId}
                  onChange={(e) => setSelectedEntityId(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-300 text-xs px-3 py-2 rounded focus:outline-none focus:border-cyber-accent font-mono"
                >
                  {graphData?.nodes.map((n) => (
                    <option key={n.data.id} value={n.data.id}>
                      [{n.data.type.toUpperCase()}] {n.data.name}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <button
              onClick={runWhatIfSimulation}
              disabled={simulatingWhatIf || !selectedEntityId}
              className="w-full py-2 bg-cyan-950/20 border border-cyber-accent/50 text-cyber-accent hover:bg-cyber-accent/10 rounded font-mono text-xs font-bold flex items-center justify-center space-x-2 transition-all"
            >
              {simulatingWhatIf ? (
                <Loader className="h-4 w-4 animate-spin" />
              ) : (
                <Play className="h-4 w-4" />
              )}
              <span>SIMULATE POTENTIAL COMPROMISE</span>
            </button>
          </div>

          {/* SIMULATION RESULTS PANEL */}
          <div className="flex-1 bg-slate-900/10 border border-slate-900 rounded-lg p-5 flex flex-col justify-center min-h-[160px]">
            {whatIfReport ? (
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs text-slate-400">
                {/* Attack Probability */}
                <div className="p-3 bg-slate-950 border border-slate-850 rounded space-y-1">
                  <span className="text-[9px] text-slate-500 font-bold uppercase">Attack Probability</span>
                  <p className="text-xl font-bold text-red-500 glow-text-red">
                    {whatIfReport.attack_path.attack_probability}%
                  </p>
                  <span className="text-[8px] text-slate-600">Conf: {whatIfReport.attack_path.confidence * 100}%</span>
                </div>

                {/* Blast Radius Loss */}
                <div className="p-3 bg-slate-950 border border-slate-850 rounded space-y-1">
                  <span className="text-[9px] text-slate-500 font-bold uppercase">Estimated Blast Loss</span>
                  <p className="text-xl font-bold text-slate-200">
                    {whatIfReport.blast_radius.formatted_exposure}
                  </p>
                  <span className="text-[8px] text-slate-600">Reachable: {whatIfReport.blast_radius.affected_accounts} accounts</span>
                </div>

                {/* Affected Customers */}
                <div className="p-3 bg-slate-950 border border-slate-850 rounded space-y-1">
                  <span className="text-[9px] text-slate-500 font-bold uppercase">Impacted Customers</span>
                  <p className="text-xl font-bold text-slate-200">
                    {whatIfReport.blast_radius.affected_customers}
                  </p>
                  <span className="text-[8px] text-slate-600">Distinct clients at risk</span>
                </div>

                {/* Reachable Traps */}
                <div className="p-3 bg-slate-950 border border-slate-850 rounded space-y-1">
                  <span className="text-[9px] text-slate-500 font-bold uppercase">Reachable Criticals</span>
                  <p className="text-xl font-bold text-purple-500">
                    {whatIfReport.blast_radius.critical_assets_count}
                  </p>
                  <span className="text-[8px] text-slate-600">Honeytokens & Admin nodes</span>
                </div>

                {/* Attack Path Chain visualization */}
                {whatIfReport.attack_path.path_nodes.length > 0 && (
                  <div className="md:col-span-4 border-t border-slate-900 pt-3 space-y-2">
                    <span className="text-[9px] text-slate-500 font-bold uppercase">Predicted Attacker Traversal Chain:</span>
                    <div className="flex flex-wrap items-center gap-2 p-3 bg-slate-950 border border-slate-900 rounded font-mono text-[10px]">
                      {whatIfReport.attack_path.path_nodes.map((node, idx) => (
                        <React.Fragment key={node.id}>
                          {idx > 0 && <ArrowRight className="h-3 w-3 text-slate-600" />}
                          <span className={`px-2 py-0.5 rounded border border-slate-850 bg-slate-900/60 font-semibold ${
                            node.label === "APIEndpoint" ? "text-purple-400" : node.label === "EmployeeCredential" ? "text-yellow-400" : "text-cyan-400"
                          }`}>
                            [{node.label.toUpperCase()}] {node.name}
                          </span>
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center text-slate-600 text-xs uppercase font-mono py-4">
                {simulatingWhatIf ? "Compiling lateral movement models..." : "Select an entry node and run What-If simulation"}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
