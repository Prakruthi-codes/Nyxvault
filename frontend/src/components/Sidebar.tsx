import { Shield, LayoutDashboard, Share2, AlertTriangle, RefreshCw, Radio } from "lucide-react";

export type PageType = "overview" | "graph" | "threats" | "mutations";

interface SidebarProps {
  activePage: PageType;
  setActivePage: (page: PageType) => void;
  wsConnected: boolean;
  alertCount: number;
}

export default function Sidebar({ activePage, setActivePage, wsConnected, alertCount }: SidebarProps) {
  const menuItems = [
    { id: "overview" as PageType, label: "Overview", icon: LayoutDashboard },
    { id: "graph" as PageType, label: "Graph Explorer", icon: Share2 },
    { 
      id: "threats" as PageType, 
      label: "Threat Center", 
      icon: AlertTriangle, 
      badge: alertCount > 0 ? alertCount : undefined,
      badgeColor: "bg-cyber-danger text-white pulse-critical"
    },
    { id: "mutations" as PageType, label: "Mutation Activity", icon: RefreshCw },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-900 flex flex-col justify-between h-screen sticky top-0">
      <div>
        {/* LOGO */}
        <div className="p-6 border-b border-slate-900 flex items-center space-x-3">
          <Shield className="h-8 w-8 text-cyber-accent animate-pulse" />
          <div>
            <h1 className="font-bold text-slate-100 text-lg tracking-wider font-mono">NYXVAULT</h1>
            <p className="text-[10px] text-cyber-accent font-semibold uppercase tracking-widest">LITE v1.0.0</p>
          </div>
        </div>

        {/* WS CONNECTION STATUS */}
        <div className="px-6 py-4 border-b border-slate-900 flex items-center justify-between">
          <span className="text-[11px] text-slate-400 font-semibold tracking-wider">SYSTEM STATUS:</span>
          <div className="flex items-center space-x-2">
            <Radio className={`h-4 w-4 ${wsConnected ? "text-cyber-success animate-ping" : "text-cyber-danger"}`} />
            <span className={`text-[10px] font-bold uppercase ${wsConnected ? "text-cyber-success" : "text-cyber-danger"}`}>
              {wsConnected ? "LIVE FEED" : "OFFLINE"}
            </span>
          </div>
        </div>

        {/* NAVIGATION LINKS */}
        <nav className="p-4 space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)}
                className={`w-full flex items-center justify-between px-4 py-3 rounded-lg text-sm font-semibold tracking-wide transition-all border font-mono ${
                  isActive
                    ? "bg-slate-900 border-cyber-accent text-cyber-accent glow-text-cyan"
                    : "border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-200"
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`h-5 w-5 ${isActive ? "text-cyber-accent" : "text-slate-500"}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* FOOTER */}
      <div className="p-6 border-t border-slate-900 text-[10px] text-slate-500 space-y-1 font-mono">
        <p>DECEPTION: ACTIVE</p>
        <p>ML ENGINE: ISO-FOREST</p>
        <p className="text-slate-600">© 2026 NyxVault Project</p>
      </div>
    </aside>
  );
}
