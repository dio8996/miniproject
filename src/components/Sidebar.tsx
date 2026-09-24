import React from 'react';
import {
  ShieldAlert,
  Activity,
  Terminal,
  Ban,
  FileCode2,
  Users,
  BarChart3,
  History,
  Sliders,
  Code
} from 'lucide-react';
import { UserRole } from '../types/security';

export type NavView =
  | 'dashboard'
  | 'monitor'
  | 'events'
  | 'ips'
  | 'rules'
  | 'users'
  | 'reports'
  | 'audit'
  | 'settings'
  | 'code';

interface SidebarProps {
  currentView: NavView;
  onSelectView: (view: NavView) => void;
  userRole: UserRole;
  blockedCount: number;
  criticalCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  userRole,
  blockedCount,
  criticalCount
}) => {
  const navItems = [
    { id: 'dashboard' as NavView, label: 'SOC Dashboard', icon: Activity },
    { id: 'monitor' as NavView, label: 'Live Security Monitor', icon: Terminal, highlight: true },
    { id: 'events' as NavView, label: 'Attack Events', icon: ShieldAlert, badge: criticalCount > 0 ? criticalCount : undefined },
    { id: 'ips' as NavView, label: 'IP Management', icon: Ban, badge: blockedCount > 0 ? blockedCount : undefined },
    { id: 'rules' as NavView, label: 'Detection Rules', icon: FileCode2 },
    { id: 'users' as NavView, label: 'Users & Roles', icon: Users },
    { id: 'reports' as NavView, label: 'Threat Reports', icon: BarChart3 },
    { id: 'audit' as NavView, label: 'Audit Logs', icon: History },
    { id: 'settings' as NavView, label: 'Engine Settings', icon: Sliders },
    { id: 'code' as NavView, label: 'Backend Source Code', icon: Code, kicker: 'Python / MySQL' }
  ];

  return (
    <aside className="w-64 bg-slate-950/95 border-r border-slate-800/80 flex flex-col shrink-0 select-none h-screen">
      {/* Brand Zone */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
            <span className="text-lg font-bold tracking-tight text-white">ZeroAttack</span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">
            Intelligent Cyber IPS
          </div>
        </div>
      </div>

      {/* Navigation Items */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectView(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'}`} />
                <span className="truncate">{item.label}</span>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {item.kicker && (
                  <span className="text-[9px] font-mono text-cyan-400/80 bg-cyan-950/60 px-1 py-0.5 rounded border border-cyan-800/30">
                    {item.kicker}
                  </span>
                )}
                {item.badge !== undefined && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                    item.id === 'events' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                  }`}>
                    {item.badge}
                  </span>
                )}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Engine Status Footer */}
      <div className="p-3.5 border-t border-slate-800/80 bg-slate-900/40 text-[11px] font-mono text-slate-400 space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Heuristic Rules:</span>
          <span className="text-emerald-400">ARMED</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Anomaly Engine:</span>
          <span className="text-cyan-400">ACTIVE (Z-Score)</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-500">Payload Cipher:</span>
          <span className="text-slate-300">AES-256-GCM</span>
        </div>
      </div>
    </aside>
  );
};
