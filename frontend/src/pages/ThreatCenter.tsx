import { useState } from "react";
import { type SecurityEvent } from "../services/api";
import { Eye, Search, Filter } from "lucide-react";

interface ThreatCenterProps {
  events: SecurityEvent[];
}

export default function ThreatCenter({ events }: ThreatCenterProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const filteredEvents = events.filter((e) => {
    const matchesSearch = 
      e.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.accessed_asset || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (e.source_ip || "").toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesType = typeFilter === "all" || e.event_type === typeFilter;
    
    return matchesSearch && matchesType;
  });

  const getRiskBadgeColor = (score: number) => {
    if (score >= 80) return "bg-red-950/40 border-red-500/60 text-red-400 font-bold pulse-critical border";
    if (score >= 50) return "bg-amber-950/30 border-amber-500/50 text-amber-400 border";
    return "bg-slate-900 border-slate-800 text-slate-400 border";
  };

  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="border-b border-slate-900 pb-4">
        <h2 className="text-xl font-bold text-slate-100 uppercase tracking-wider font-mono">THREAT DETECT HUB</h2>
        <p className="text-xs text-slate-500">Live auditing log stream of Isolation Forest alerts and Honeytoken traps.</p>
      </div>

      {/* FILTER SEARCH TOOLS */}
      <div className="flex flex-col md:flex-row space-y-3 md:space-y-0 md:space-x-4 bg-slate-950 p-4 border border-slate-900 rounded-lg">
        <div className="flex-1 relative flex items-center">
          <Search className="h-4 w-4 text-slate-500 absolute left-3" />
          <input
            type="text"
            placeholder="Search by asset, IP, descriptions..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 text-slate-300 text-xs pl-10 pr-4 py-2 rounded focus:outline-none focus:border-cyber-accent font-mono"
          />
        </div>
        <div className="flex items-center space-x-3">
          <Filter className="h-4 w-4 text-slate-500" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-400 text-xs px-3 py-2 rounded focus:outline-none focus:border-cyber-accent font-mono"
          >
            <option value="all">ALL EVENT TYPES</option>
            <option value="attack">SIMULATOR ATTACKS</option>
            <option value="detection">SECURITY ALERTS</option>
            <option value="mutation">DECEPTION MUTATIONS</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* LOG STREAM TABLE */}
        <div className="xl:col-span-2 bg-slate-950 border border-slate-900 rounded-lg overflow-hidden flex flex-col h-[550px]">
          <div className="bg-slate-900/60 px-5 py-3 border-b border-slate-900 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Event Log Timeline</span>
            <span className="text-[10px] text-slate-500 font-semibold font-mono">COUNT: {filteredEvents.length}</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-slate-900/60">
            {filteredEvents.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-600 text-xs uppercase font-mono">
                No system alerts captured.
              </div>
            ) : (
              filteredEvents.map((e) => (
                <div
                  key={e.event_id}
                  onClick={() => setSelectedEvent(e)}
                  className={`p-4 hover:bg-slate-900/30 cursor-pointer transition-all flex flex-col md:flex-row md:items-center justify-between space-y-2 md:space-y-0 ${
                    selectedEvent?.event_id === e.event_id ? "bg-slate-900/40 border-l-2 border-cyber-accent" : ""
                  }`}
                >
                  <div className="space-y-1 md:pr-4 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wide ${
                        e.event_type === "attack" 
                          ? "bg-red-950/20 text-red-500" 
                          : e.event_type === "detection"
                          ? "bg-cyan-950/20 text-cyber-accent"
                          : "bg-amber-950/20 text-amber-500"
                      }`}>
                        {e.event_type}
                      </span>
                      <span className="text-xs font-bold text-slate-300 font-mono leading-none">{e.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-500 font-mono line-clamp-1">{e.description}</p>
                    <div className="flex items-center space-x-4 text-[10px] text-slate-600">
                      <span>IP: {e.source_ip || "LOCAL"}</span>
                      {e.accessed_asset && <span>ASSET: {e.accessed_asset}</span>}
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 md:justify-end">
                    <span className="text-[10px] text-slate-600 font-mono">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </span>
                    {e.risk_score > 0 && (
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${getRiskBadgeColor(e.risk_score)}`}>
                        RISK: {e.risk_score}%
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* DETAILED EXAMINER PANEL */}
        <div className="bg-slate-950 border border-slate-900 rounded-lg p-5 flex flex-col justify-between h-[550px] overflow-y-auto">
          {selectedEvent ? (
            <div className="space-y-5 flex-1 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-900 pb-3">
                  <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Audit Detail Panel</span>
                  <span className="text-[10px] text-slate-500 font-mono">ID: {selectedEvent.event_id.substring(0, 8)}</span>
                </div>

                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-slate-200">{selectedEvent.title}</h4>
                  <p className="text-xs text-slate-400 font-mono">{selectedEvent.description}</p>
                </div>

                {/* RISK GAUGE */}
                {selectedEvent.risk_score > 0 && (
                  <div className="p-4 bg-slate-900/35 border border-slate-900 rounded-lg space-y-2">
                    <div className="flex justify-between items-center text-xs font-bold font-mono">
                      <span className="text-slate-400">THREAT RISK COEFFICIENT:</span>
                      <span className={selectedEvent.risk_score >= 80 ? "text-red-500" : "text-amber-500"}>
                        {selectedEvent.risk_score}%
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-950 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${selectedEvent.risk_score >= 80 ? "bg-red-500 pulse-critical" : "bg-amber-500"}`} 
                        style={{ width: `${selectedEvent.risk_score}%` }}
                      ></div>
                    </div>
                  </div>
                )}

                {/* ML CLASSIFIER STATS */}
                {selectedEvent.threat_type && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 bg-slate-900/20 border border-slate-900 rounded space-y-1">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Threat Class</span>
                      <p className="text-xs font-bold text-slate-300 font-mono">{selectedEvent.threat_type}</p>
                    </div>
                    <div className="p-3 bg-slate-900/20 border border-slate-900 rounded space-y-1">
                      <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">ML Confidence</span>
                      <p className="text-xs font-bold text-slate-300 font-mono">{(selectedEvent.confidence || 0) * 100}%</p>
                    </div>
                  </div>
                )}

                {/* TRANSACTION / ACTION PAYLOAD DETAILS */}
                <div className="space-y-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase font-mono">Captured Payload:</span>
                  <pre className="p-3 bg-slate-900 text-[10px] text-slate-400 font-mono rounded border border-slate-900 overflow-x-auto">
                    {JSON.stringify(selectedEvent.details, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="pt-4 border-t border-slate-900 text-[10px] text-slate-500 space-y-1 font-mono">
                <p>AUDIT TIMESTAMP: {new Date(selectedEvent.timestamp).toLocaleString()}</p>
                <p>SOURCE DEVICE IP: {selectedEvent.source_ip || "INTERNAL_DAEMON"}</p>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-600 text-xs uppercase font-mono space-y-3">
              <Eye className="h-8 w-8 text-slate-700" />
              <span>Select an alert to inspect payload</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
