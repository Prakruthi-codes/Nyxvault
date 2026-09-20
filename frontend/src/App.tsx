import { useState, useEffect, useCallback } from "react";
import Sidebar, { type PageType } from "./components/Sidebar";
import Overview from "./pages/Overview";
import GraphExplorer from "./pages/GraphExplorer";
import ThreatCenter from "./pages/ThreatCenter";
import MutationActivity from "./pages/MutationActivity";

import { useWebSocket } from "./services/websocket";
import { apiService, type SystemStats, type SecurityEvent } from "./services/api";

export default function App() {
  const [activePage, setActivePage] = useState<PageType>("overview");
  
  // App States
  const [stats, setStats] = useState<SystemStats>({
    total_customers: 0,
    total_accounts: 0,
    total_transactions: 0,
    active_threats: 0,
    mutation_count: 0,
    threat_score_distribution: {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0
    },
    predicted_financial_exposure: 0,
    formatted_exposure: "₹0.00 Lakh",
    fraud_rings_count: 0,
    attack_probability_forecast: 0,
    honeytoken_activations: 0,
    blast_radius_summary: {
      avg_affected_accounts: 0,
      avg_affected_customers: 0
    }
  });
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alertedNodes, setAlertedNodes] = useState<string[]>([]);

  // Fetch status metrics
  const fetchStatusMetrics = async () => {
    try {
      const currentStats = await apiService.getStats();
      setStats(currentStats);
    } catch (e) {
      console.error("Failed to load backend configurations & stats:", e);
    }
  };

  useEffect(() => {
    fetchStatusMetrics();
  }, []);

  // Handle incoming real-time socket events
  const handleIncomingEvent = useCallback((event: SecurityEvent) => {
    // Prepends new events to local stream logs
    setEvents((prev) => [event, ...prev]);

    // Handle stats counters updates based on event payload
    if (event.event_type === "detection") {
      if (event.risk_score >= 85.0) {
        setStats((prev) => ({
          ...prev,
          active_threats: prev.active_threats + 1,
        }));
      }

      // Highlight target node in Cytoscape canvas
      if (event.accessed_asset) {
        const nodeId = event.accessed_asset;
        setAlertedNodes((prev) => [...prev, nodeId]);
        
        // Remove node glow alert highlight after 10 seconds
        setTimeout(() => {
          setAlertedNodes((prev) => prev.filter((id) => id !== nodeId));
        }, 10000);
      }
    } else if (event.event_type === "mutation") {
      setStats((prev) => ({
        ...prev,
        mutation_count: (event.details?.mutation_cycle as number) || (prev.mutation_count + 1),
      }));
    }
  }, []);

  // Establish WebSocket connection
  const { isConnected: wsConnected } = useWebSocket(handleIncomingEvent);

  const getActiveView = () => {
    switch (activePage) {
      case "overview":
        return (
          <Overview
            stats={stats}
            onRefresh={fetchStatusMetrics}
          />
        );
      case "graph":
        return <GraphExplorer alertedNodes={alertedNodes} />;
      case "threats":
        return <ThreatCenter events={events} />;
      case "mutations":
        return <MutationActivity events={events} />;
      default:
        return <div className="text-slate-500 font-mono">Select a panel from side navigation.</div>;
    }
  };

  return (
    <div className="flex bg-cyber-bg min-h-screen text-cyber-text">
      {/* SIDEBAR */}
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        wsConnected={wsConnected}
        alertCount={events.filter((e) => e.event_type === "detection" && e.risk_score >= 85.0).length}
      />

      {/* CORE WORKSPACE PANEL */}
      <main className="flex-1 p-8 h-screen overflow-y-auto">
        {getActiveView()}
      </main>
    </div>
  );
}
