import { useEffect, useRef, useState, Fragment } from "react";
import cytoscape from "cytoscape";
import { apiService, type CytoscapeGraph, type CytoscapeNodeData, type EntityRiskReport } from "../services/api";
import { 
  Network, ZoomIn, ZoomOut, Maximize2, Info, Key, Code2, 
  UserCheck, ShieldAlert, ArrowRight, Loader 
} from "lucide-react";

interface GraphExplorerProps {
  alertedNodes: string[];
}

interface ExtendedNodeData extends CytoscapeNodeData {
  risk_level?: string;
  fraud_ring_id?: string | null;
}

export default function GraphExplorer({ alertedNodes }: GraphExplorerProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  
  const [graphData, setGraphData] = useState<CytoscapeGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<ExtendedNodeData | null>(null);
  const [riskReport, setRiskReport] = useState<EntityRiskReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  
  // Filtering Options
  const [txLimit, setTxLimit] = useState(150);
  const [showAPIs, setShowAPIs] = useState(true);
  const [showCreds, setShowCreds] = useState(true);

  // Fetch data
  const fetchGraph = async () => {
    setLoading(true);
    try {
      const data = await apiService.getGraphData(txLimit);
      setGraphData(data);
    } catch (e) {
      console.error("Failed to load graph data:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, [txLimit]);

  // Render cytoscape canvas
  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    // Filter nodes/edges based on states
    let filteredNodes = [...graphData.nodes];
    if (!showAPIs) {
      filteredNodes = filteredNodes.filter((n) => n.data.type !== "APIEndpoint");
    }
    if (!showCreds) {
      filteredNodes = filteredNodes.filter((n) => n.data.type !== "EmployeeCredential");
    }

    // Elevate details like risk_level and fraud_ring_id to top-level data properties
    const mappedNodes = filteredNodes.map((n) => {
      const details = n.data.details || {};
      const riskLevel = details.risk_level || "LOW";
      const fraudRingId = details.fraud_ring_id || null;
      return {
        ...n,
        data: {
          ...n.data,
          risk_level: riskLevel,
          fraud_ring_id: fraudRingId,
        },
      };
    });

    const filteredNodeIds = new Set(mappedNodes.map((n) => n.data.id));
    const filteredEdges = graphData.edges.filter(
      (e) => filteredNodeIds.has(e.data.source) && filteredNodeIds.has(e.data.target)
    );

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: [...mappedNodes, ...filteredEdges],
      style: [
        {
          selector: "node",
          style: {
            "label": "data(name)",
            "color": "#94a3b8",
            "font-size": "7px",
            "font-family": "monospace",
            "background-color": "#0f172a",
            "border-width": "1.5px",
            "border-color": "#475569",
            "width": "16px",
            "height": "16px",
            "text-valign": "bottom",
            "text-margin-y": 3,
            "transition-property": "background-color border-color border-width width height",
            "transition-duration": 0.3,
          },
        },
        // Shapes by Type
        {
          selector: "node[type='Customer']",
          style: {
            "width": "16px",
            "height": "16px",
          },
        },
        {
          selector: "node[type='Account']",
          style: {
            "shape": "round-rectangle",
            "width": "16px",
            "height": "16px",
          },
        },
        {
          selector: "node[type='APIEndpoint']",
          style: {
            "shape": "hexagon",
            "width": "18px",
            "height": "18px",
          },
        },
        {
          selector: "node[type='EmployeeCredential']",
          style: {
            "shape": "diamond",
            "width": "16px",
            "height": "16px",
          },
        },
        // Risk Levels Colors (LOW = cyan, MEDIUM = yellow, HIGH = orange, CRITICAL = red pulse)
        {
          selector: "node[risk_level='LOW']",
          style: {
            "border-color": "#06b6d4",
            "background-color": "#082f49",
          },
        },
        {
          selector: "node[risk_level='MEDIUM']",
          style: {
            "border-color": "#eab308",
            "background-color": "#713f12",
          },
        },
        {
          selector: "node[risk_level='HIGH']",
          style: {
            "border-color": "#f97316",
            "background-color": "#431407",
          },
        },
        {
          selector: "node[risk_level='CRITICAL']",
          style: {
            "border-color": "#ef4444",
            "background-color": "#7f1d1d",
            "border-width": "3px",
          },
        },
        // Fraud Ring Border Styling (special ring border)
        {
          selector: "node[fraud_ring_id][fraud_ring_id != '']",
          style: {
            "border-style": "dashed",
            "border-width": "3px",
            "border-color": "#c084fc",
          },
        },
        // Honeytokens Border Styling (neon fuchsia warning border)
        {
          selector: "node[is_honeytoken=true]",
          style: {
            "border-color": "#d946ef",
            "border-width": "3.5px",
            "border-style": "double",
          },
        },
        // Selected Node Highlight
        {
          selector: "node:selected",
          style: {
            "border-color": "#38bdf8",
            "border-width": "3px",
            "background-color": "#0c4a6e",
          },
        },
        // Attack Path Node Highlight
        {
          selector: "node.attack-path-node",
          style: {
            "border-color": "#f43f5e",
            "border-width": "4px",
            "width": "22px",
            "height": "22px",
            "background-color": "#881337",
          },
        },
        // Edges styling
        {
          selector: "edge",
          style: {
            "width": "1px",
            "line-color": "#334155",
            "curve-style": "bezier",
            "opacity": 0.4,
          },
        },
        {
          selector: "edge[type='OWNS']",
          style: {
            "line-color": "#0d9488",
          },
        },
        {
          selector: "edge[type='HAS_CREDENTIAL']",
          style: {
            "line-color": "#d97706",
            "line-style": "dashed",
          },
        },
        {
          selector: "edge[type='TRANSFERRED_TO']",
          style: {
            "line-color": "#3b82f6",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#3b82f6",
            "opacity": 0.6,
          },
        },
        // Attack Path Edge Highlight
        {
          selector: "edge.attack-path-edge",
          style: {
            "line-color": "#ef4444",
            "width": "3.5px",
            "opacity": 1.0,
            "target-arrow-color": "#ef4444",
            "target-arrow-shape": "triangle",
          },
        },
        // Dimming elements not in path
        {
          selector: ".dimmed",
          style: {
            "opacity": 0.15,
          },
        },
      ],
      layout: {
        name: "cose",
        idealEdgeLength: () => 32,
        nodeOverlap: 20,
        refresh: 20,
        fit: true,
        padding: 30,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: () => 400000,
        edgeElasticity: () => 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
      },
    });

    cyRef.current = cy;

    // Handle Selection Events
    cy.on("select", "node", async (event) => {
      const node = event.target;
      const nodeData = node.data();
      setSelectedNode(nodeData);
      setRiskReport(null);
      setReportLoading(true);

      // Clear any previous highlights
      cy.elements().removeClass("dimmed").removeClass("attack-path-node").removeClass("attack-path-edge");

      try {
        const report = await apiService.getEntityRiskReport(nodeData.id);
        setRiskReport(report);

        // Highlight attack path nodes and edges if available
        if (report.attack_path && report.attack_path.path_nodes && report.attack_path.path_nodes.length > 1) {
          const pathNodeIds = report.attack_path.path_nodes.map((n) => n.id);
          
          // First, dim all elements
          cy.elements().addClass("dimmed");

          // Highlight path nodes that are visible
          pathNodeIds.forEach((id) => {
            const cyNode = cy.nodes(`[id="${id}"]`);
            if (cyNode.length > 0) {
              cyNode.removeClass("dimmed").addClass("attack-path-node");
            }
          });

          // Highlight path edges connecting consecutive path nodes
          for (let i = 0; i < pathNodeIds.length - 1; i++) {
            const source = pathNodeIds[i];
            const target = pathNodeIds[i + 1];
            const cyEdges = cy.edges(`[source="${source}"][target="${target}"]`);
            if (cyEdges.length > 0) {
              cyEdges.removeClass("dimmed").addClass("attack-path-edge");
            }
          }
        }
      } catch (err) {
        console.error("Failed to load entity risk report:", err);
      } finally {
        setReportLoading(false);
      }
    });

    cy.on("unselect", "node", () => {
      setSelectedNode(null);
      setRiskReport(null);
      
      // Clear path highlights
      cy.elements().removeClass("dimmed").removeClass("attack-path-node").removeClass("attack-path-edge");
    });

    return () => {
      cy.destroy();
    };
  }, [graphData, showAPIs, showCreds]);

  // Handle live alert updates in cy-canvas
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    // Remove old alerted class
    cy.nodes().removeClass("alerted");

    // Add alerted class to matching node IDs
    if (alertedNodes.length > 0) {
      alertedNodes.forEach((nodeId) => {
        cy.nodes(`[id="${nodeId}"]`).addClass("alerted");
      });
    }
  }, [alertedNodes, graphData]);

  // Graph Canvas Helper controls
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit();

  // Helper formatting styles
  const getRiskColorClass = (level: string) => {
    switch (level) {
      case "CRITICAL": return "bg-red-950 text-red-400 border border-red-800/50";
      case "HIGH": return "bg-orange-950 text-orange-400 border border-orange-850/50";
      case "MEDIUM": return "bg-yellow-950 text-yellow-400 border border-yellow-850/50";
      default: return "bg-cyan-950 text-cyan-400 border border-cyan-850/50";
    }
  };

  const getRiskTextClass = (level: string) => {
    switch (level) {
      case "CRITICAL": return "text-red-500 animate-pulse";
      case "HIGH": return "text-orange-500";
      case "MEDIUM": return "text-yellow-500";
      default: return "text-cyan-500";
    }
  };

  const getRiskBgClass = (level: string) => {
    switch (level) {
      case "CRITICAL": return "bg-red-505 bg-red-500";
      case "HIGH": return "bg-orange-500";
      case "MEDIUM": return "bg-yellow-500";
      default: return "bg-cyan-500";
    }
  };

  const getEntityIcon = (type: string) => {
    switch (type) {
      case "EmployeeCredential": return <Key className="h-3.5 w-3.5 text-yellow-500" />;
      case "APIEndpoint": return <Code2 className="h-3.5 w-3.5 text-purple-500" />;
      case "Customer": return <UserCheck className="h-3.5 w-3.5 text-cyan-500" />;
      default: return <Info className="h-3.5 w-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6 font-mono">
      {/* HEADER */}
      <div className="flex justify-between items-center border-b border-slate-900 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 uppercase tracking-wider">GRAPH EXPLORER</h2>
          <p className="text-xs text-slate-500">Interactive Cytoscape.js modeling of accounts, APIs, logins, and threat alerts.</p>
        </div>
        <button
          onClick={fetchGraph}
          className="px-4 py-2 border border-slate-800 hover:border-cyber-accent text-slate-300 hover:text-cyber-accent bg-slate-900 rounded text-xs font-semibold flex items-center space-x-2 transition-all"
        >
          <Maximize2 className="h-3 w-3" />
          <span>RE-CENTER NETWORK</span>
        </button>
      </div>

      {/* CANVAS SECTION */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* FILTERS & LEGENDS PANEL */}
        <div className="bg-slate-950 border border-slate-900 rounded-lg p-5 space-y-6">
          {/* FILTER CONTROLS */}
          <div className="space-y-4">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-900 pb-2">
              Visual Filters
            </h3>
            
            <div className="space-y-3 text-xs">
              <label className="flex items-center space-x-2.5 cursor-pointer text-slate-300 hover:text-slate-200">
                <input
                  type="checkbox"
                  checked={showAPIs}
                  onChange={(e) => setShowAPIs(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-800 text-cyber-accent focus:ring-0"
                />
                <span>SHOW API ENDPOINTS</span>
              </label>

              <label className="flex items-center space-x-2.5 cursor-pointer text-slate-300 hover:text-slate-200">
                <input
                  type="checkbox"
                  checked={showCreds}
                  onChange={(e) => setShowCreds(e.target.checked)}
                  className="rounded bg-slate-900 border-slate-800 text-cyber-accent focus:ring-0"
                />
                <span>SHOW LOGIN CREDENTIALS</span>
              </label>

              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 font-bold uppercase">Transaction Edges Limit:</span>
                <select
                  value={txLimit}
                  onChange={(e) => setTxLimit(Number(e.target.value))}
                  className="w-full bg-slate-900 border border-slate-800 text-slate-400 text-[11px] px-2 py-1.5 rounded focus:outline-none focus:border-cyber-accent"
                >
                  <option value="50">50 EDGES (CLEAREST)</option>
                  <option value="150">150 EDGES (BALANCED)</option>
                  <option value="400">400 EDGES (DENSE)</option>
                </select>
              </div>
            </div>
          </div>

          {/* COLOR CODED LEGEND */}
          <div className="space-y-4">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider border-b border-slate-900 pb-2">
              Graph Legend
            </h3>
            
            <div className="space-y-2 text-[11px] text-slate-400">
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 rounded border border-cyan-500 bg-cyan-950/20"></span>
                <span>LOW RISK</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 rounded border border-yellow-500 bg-yellow-950/20"></span>
                <span>MEDIUM RISK</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 rounded border border-orange-500 bg-orange-950/20"></span>
                <span>HIGH RISK</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 rounded border-2 border-red-500 bg-red-950/20"></span>
                <span>CRITICAL RISK</span>
              </div>
              <div className="border-t border-slate-900 my-2"></div>
              <div className="flex items-center space-x-3">
                <span className="h-3.5 w-3.5 border-2 border-double border-fuchsia-500 bg-fuchsia-950/20 rounded-full"></span>
                <span className="text-fuchsia-400 font-semibold">DECEPTION TRAP</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 border-2 border-dashed border-purple-400 rounded-full bg-purple-950/20"></span>
                <span className="text-purple-300 font-semibold">FRAUD RING</span>
              </div>
              <div className="flex items-center space-x-3">
                <span className="h-3 w-3 rounded-full bg-red-500 animate-ping"></span>
                <span className="text-red-500 font-bold uppercase">ACTIVE THREAT</span>
              </div>
            </div>
          </div>
        </div>

        {/* INTERACTIVE CANVAS */}
        <div className="lg:col-span-3 bg-slate-950 border border-slate-900 rounded-lg h-[570px] relative overflow-hidden flex">
          {loading && (
            <div className="absolute inset-0 bg-slate-950/70 z-10 flex items-center justify-center text-slate-400 text-xs font-semibold space-x-2">
              <div className="h-4 w-4 border-2 border-cyber-accent border-t-transparent rounded-full animate-spin"></div>
              <span>COMPILING GRAPH NETWORK...</span>
            </div>
          )}

          {/* CANVAS MOUNT ELEMENT */}
          <div ref={containerRef} className="flex-1 h-full z-0 cursor-grab active:cursor-grabbing"></div>

          {/* CANVAS FLOATING ZOOM CONTROLS */}
          <div className="absolute bottom-4 left-4 z-10 flex space-x-2 bg-slate-900/80 p-2 border border-slate-800 rounded shadow-md">
            <button onClick={handleZoomIn} className="p-1 hover:text-cyber-accent text-slate-400" title="Zoom In"><ZoomIn className="h-4 w-4" /></button>
            <button onClick={handleZoomOut} className="p-1 hover:text-cyber-accent text-slate-400" title="Zoom Out"><ZoomOut className="h-4 w-4" /></button>
            <button onClick={handleFit} className="p-1 hover:text-cyber-accent text-slate-400" title="Auto Fit"><Network className="h-4 w-4" /></button>
          </div>

          {/* FLOATING DETAIL DRAWER */}
          {selectedNode && (
            <div className="absolute top-4 right-4 z-10 w-96 bg-slate-950/95 border border-slate-800 rounded-lg p-5 shadow-2xl space-y-4 max-h-[92%] overflow-y-auto backdrop-blur-md transition-all font-mono text-xs">
              <div className="flex justify-between items-start border-b border-slate-900 pb-3">
                <div className="space-y-1">
                  <span className="text-[9px] font-bold text-cyber-accent tracking-widest uppercase flex items-center space-x-1">
                    {getEntityIcon(selectedNode.type)}
                    <span>{selectedNode.type} PROFILE</span>
                  </span>
                  <h3 className="font-bold text-slate-100 uppercase tracking-wide truncate max-w-[200px]" title={selectedNode.name}>
                    {selectedNode.name}
                  </h3>
                  <span className="text-[9px] text-slate-500 block">ID: {selectedNode.id}</span>
                </div>
                <div className="flex flex-col items-end space-y-1.5">
                  <button 
                    onClick={() => {
                      cyRef.current?.nodes(`[id="${selectedNode.id}"]`).unselect();
                    }}
                    className="text-slate-500 hover:text-slate-300 text-[10px] uppercase font-bold"
                  >
                    [Close]
                  </button>
                  {selectedNode.is_honeytoken && (
                    <span className="text-[9px] px-2 py-0.5 bg-fuchsia-950 text-fuchsia-400 font-bold border border-fuchsia-800/50 rounded animate-pulse uppercase tracking-wider">
                      DECOY TRAP
                    </span>
                  )}
                </div>
              </div>

              {reportLoading ? (
                <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-500">
                  <Loader className="h-6 w-6 animate-spin text-cyber-accent" />
                  <span className="text-[10px] tracking-wider uppercase">QUERYING THREAT INTEL...</span>
                </div>
              ) : riskReport ? (
                <div className="space-y-5">
                  {/* Threat Score & Risk Level */}
                  <div className="p-4 bg-slate-900/40 border border-slate-900 rounded-lg space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider font-mono">PREDICTIVE THREAT SCORE</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                        getRiskColorClass(riskReport.entity.risk_level)
                      }`}>
                        {riskReport.entity.risk_level}
                      </span>
                    </div>
                    <div className="flex items-baseline space-x-2">
                      <span className={`text-4xl font-extrabold tracking-tight ${
                        getRiskTextClass(riskReport.entity.risk_level)
                      }`}>
                        {Math.round(riskReport.entity.threat_score)}
                      </span>
                      <span className="text-slate-500 font-bold text-sm">/ 100</span>
                    </div>
                    <div className="h-1.5 bg-slate-950 rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${getRiskBgClass(riskReport.entity.risk_level)}`} 
                        style={{ width: `${riskReport.entity.threat_score}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* AI Explanation */}
                  <div className="space-y-2">
                    <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block">AI COGNITIVE ANALYSIS</span>
                    <div className="p-3.5 bg-slate-950 border border-slate-905 border-slate-900 rounded-lg border-l-2 border-l-cyber-accent space-y-2.5">
                      <p className="text-slate-300 leading-relaxed text-[11px] font-sans">
                        {riskReport.ai_explanation.explanation}
                      </p>
                      <div className="flex justify-between items-center text-[9px] text-slate-500 border-t border-slate-900 pt-2 font-mono">
                        <span>CONFIDENCE SCORE</span>
                        <span className="text-slate-300 font-bold">{Math.round(riskReport.ai_explanation.confidence * 100)}%</span>
                      </div>
                    </div>
                  </div>

                  {/* Behavioral Anomaly Profile */}
                  <div className="space-y-2">
                    <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block">BEHAVIORAL ANOMALY PROFILE</span>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2.5 bg-slate-900/20 border border-slate-900 rounded space-y-0.5">
                        <span className="text-[8px] text-slate-500 font-bold uppercase block">OUTLIER SCORE</span>
                        <span className={`font-bold ${riskReport.entity.is_anomalous ? "text-amber-500" : "text-slate-300"}`}>
                          {riskReport.entity.anomaly_score.toFixed(3)}
                        </span>
                      </div>
                      <div className="p-2.5 bg-slate-900/20 border border-slate-900 rounded space-y-0.5">
                        <span className="text-[8px] text-slate-500 font-bold uppercase block">STATUS</span>
                        <span className={`font-bold ${riskReport.entity.is_anomalous ? "text-amber-500 animate-pulse" : "text-emerald-500"}`}>
                          {riskReport.entity.is_anomalous ? "ANOMALOUS" : "NORMAL"}
                        </span>
                      </div>
                      {riskReport.entity.is_anomalous && riskReport.entity.anomaly_reason && (
                        <div className="col-span-2 p-2.5 bg-amber-950/10 border border-amber-900/30 rounded text-[10px] text-amber-400 font-sans leading-relaxed">
                          <span className="font-bold font-mono text-[8px] uppercase tracking-wider block mb-1">DETECTION SIGNAL:</span>
                          {riskReport.entity.anomaly_reason}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Fraud Ring Details */}
                  {riskReport.entity.fraud_ring_id && (
                    <div className="p-3 bg-purple-950/10 border border-purple-900/40 rounded-lg space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-[9px] text-purple-400 font-bold uppercase tracking-wider">FRAUD RING DETECTED</span>
                        <span className="text-[8px] px-1.5 py-0.5 bg-purple-900 text-purple-200 rounded font-bold uppercase">
                          RING #{riskReport.entity.fraud_ring_id.substring(0, 8)}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
                        <div>
                          <span className="text-[8px] text-slate-500 block">RING SIZE</span>
                          <span className="font-bold text-purple-300">{riskReport.entity.fraud_ring_size} Members</span>
                        </div>
                        <div>
                          <span className="text-[8px] text-slate-500 block">RING RISK</span>
                          <span className="font-bold text-purple-300">{riskReport.entity.fraud_ring_risk}%</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Financial Blast Radius */}
                  <div className="space-y-2">
                    <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block">FINANCIAL BLAST RADIUS</span>
                    <div className="p-3 bg-slate-900/20 border border-slate-900 rounded-lg space-y-3">
                      <div className="flex justify-between items-baseline">
                        <span className="text-[9px] text-slate-500 uppercase font-bold">POTENTIAL LOSS</span>
                        <span className="text-sm font-extrabold text-slate-200">{riskReport.blast_radius.formatted_exposure}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[10px]">
                        <div className="p-2 bg-slate-950 border border-slate-900 rounded">
                          <span className="text-[8px] text-slate-500 block">AFFECTED ACCTS</span>
                          <span className="font-bold text-slate-300">{riskReport.blast_radius.affected_accounts}</span>
                        </div>
                        <div className="p-2 bg-slate-950 border border-slate-900 rounded">
                          <span className="text-[8px] text-slate-500 block">AFFECTED CLIENTS</span>
                          <span className="font-bold text-slate-300">{riskReport.blast_radius.affected_customers}</span>
                        </div>
                      </div>

                      {/* Critical Assets List */}
                      {riskReport.blast_radius.critical_assets && riskReport.blast_radius.critical_assets.length > 0 && (
                        <div className="space-y-1.5 border-t border-slate-900 pt-2.5">
                          <span className="text-[8px] text-slate-500 font-bold uppercase block">CRITICAL ASSETS EXPOSED:</span>
                          <div className="space-y-1 max-h-[80px] overflow-y-auto pr-1">
                            {riskReport.blast_radius.critical_assets.map(asset => (
                              <div key={asset.id} className="flex justify-between items-center text-[10px] p-1 border border-slate-900 bg-slate-950 rounded">
                                <span className="font-semibold text-slate-400 truncate max-w-[120px]">{asset.name}</span>
                                <span className="text-[8px] text-purple-400 uppercase font-bold">{asset.label}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Attack Path Chain */}
                  {riskReport.attack_path && riskReport.attack_path.path_nodes && riskReport.attack_path.path_nodes.length > 1 && (
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider">LATERAL PATH SIMULATION</span>
                        <span className="text-[9px] text-red-400 font-bold">{riskReport.attack_path.attack_probability}% Probability</span>
                      </div>
                      <div className="p-3 bg-slate-950 border border-slate-900 rounded-lg space-y-2">
                        <span className="text-[8px] text-slate-500 font-bold uppercase block">PREDICTED ATTACK CHAIN:</span>
                        <div className="space-y-1.5 max-h-[120px] overflow-y-auto pr-1">
                          {riskReport.attack_path.path_nodes.map((pathNode, idx) => (
                            <Fragment key={pathNode.id}>
                              {idx > 0 && (
                                <div className="pl-3.5 py-0.5">
                                  <ArrowRight className="h-3.5 w-3.5 text-slate-600 rotate-90" />
                                </div>
                              )}
                              <div className="flex items-center space-x-2 text-[10px]">
                                <span className="text-slate-600 font-bold">#{idx+1}</span>
                                <span className={`px-1.5 py-0.5 rounded border border-slate-900 font-mono text-[9px] truncate max-w-[200px] ${
                                  pathNode.label === "APIEndpoint" ? "bg-purple-950/20 text-purple-400 border-purple-900/30" : 
                                  pathNode.label === "EmployeeCredential" ? "bg-yellow-950/20 text-yellow-400 border-yellow-900/30" : 
                                  "bg-cyan-950/20 text-cyan-400 border-cyan-900/30"
                                }`}>
                                  [{pathNode.label.substring(0, 4).toUpperCase()}] {pathNode.name}
                                </span>
                              </div>
                            </Fragment>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Recommended Action */}
                  <div className="space-y-2 border-t border-slate-900 pt-4">
                    <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block">SOC MITIGATION ACTIONS</span>
                    <div className="p-3 bg-red-950/10 border border-red-900/30 rounded-lg text-[10px] text-red-400 font-sans leading-relaxed flex items-start space-x-2">
                      <ShieldAlert className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
                      <span>{riskReport.ai_explanation.recommended_action}</span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-20 text-center text-slate-600 text-[10px] uppercase font-bold">
                  Failed to fetch full risk metrics.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
