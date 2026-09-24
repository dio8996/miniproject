import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Bell, Zap, UserCheck, ChevronDown } from 'lucide-react';
import { UserRole, SystemMetrics, SecurityEvent } from '../types/security';

interface HeaderProps {
  title: string;
  subtitle: string;
  metrics: SystemMetrics;
  userRole: UserRole;
  onRoleChange: (role: UserRole) => void;
  onOpenSimulator: () => void;
  recentCriticalEvents: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const Header: React.FC<HeaderProps> = ({
  title,
  subtitle,
  metrics,
  userRole,
  onRoleChange,
  onOpenSimulator,
  recentCriticalEvents,
  onSelectEvent
}) => {
  const [roleDropdownOpen, setRoleDropdownOpen] = useState(false);
  const [alertsOpen, setAlertsOpen] = useState(false);

  const roles: UserRole[] = ['ADMIN', 'SECURITY ANALYST', 'VIEWER'];

  return (
    <header className="h-16 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md px-6 flex items-center justify-between shrink-0 z-20">
      {/* Zone 1: Breadcrumb & View Info */}
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold text-white tracking-tight">{title}</h1>
        <span className="text-slate-600">/</span>
        <span className="text-xs text-slate-400 font-mono hidden sm:inline">{subtitle}</span>
      </div>

      {/* Zone 2 & 3: Threat Indicators & Actions */}
      <div className="flex items-center gap-4">
        {/* Posture Pill */}
        <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono">
          {metrics.currentRiskLevel.includes('CRITICAL') ? (
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
          ) : (
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          )}
          <span className="text-slate-400">Posture:</span>
          <span className={`font-semibold ${
            metrics.currentRiskLevel.includes('CRITICAL')
              ? 'text-rose-400'
              : metrics.currentRiskLevel.includes('HIGH')
              ? 'text-amber-400'
              : 'text-emerald-400'
          }`}>
            {metrics.currentRiskLevel}
          </span>
        </div>

        {/* Quick Launch Simulator */}
        <button
          onClick={onOpenSimulator}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-cyan-300 bg-cyan-950/80 border border-cyan-800/80 hover:bg-cyan-900 hover:border-cyan-600 rounded-lg transition-all shadow-sm"
        >
          <Zap className="w-3.5 h-3.5 text-cyan-400" />
          <span>Test Live Simulator</span>
        </button>

        {/* Alerts Notification Button */}
        <div className="relative">
          <button
            onClick={() => setAlertsOpen(!alertsOpen)}
            className="relative p-2 text-slate-400 hover:text-white hover:bg-slate-900 rounded-lg border border-slate-800 transition"
            title="Active Security Alerts"
          >
            <Bell className="w-4 h-4" />
            {recentCriticalEvents.length > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            )}
          </button>

          {alertsOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-3 z-50 text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="font-semibold text-white">Active Threat Alerts</span>
                <span className="text-[10px] font-mono text-slate-400">{recentCriticalEvents.length} High/Critical</span>
              </div>
              <div className="mt-2 space-y-2 max-h-60 overflow-y-auto font-mono">
                {recentCriticalEvents.length === 0 ? (
                  <p className="text-slate-500 p-3 text-center">No active critical threats.</p>
                ) : (
                  recentCriticalEvents.map(ev => (
                    <div
                      key={ev.id}
                      onClick={() => {
                        onSelectEvent(ev);
                        setAlertsOpen(false);
                      }}
                      className="p-2 rounded bg-slate-950 border border-rose-950/60 hover:border-rose-700 cursor-pointer transition"
                    >
                      <div className="flex justify-between items-center text-[11px]">
                        <span className="text-rose-400 font-bold">{ev.attackType}</span>
                        <span className="text-slate-400">{ev.riskScore}/100</span>
                      </div>
                      <div className="text-[10px] text-slate-300 truncate mt-0.5">{ev.sourceIp} &bull; {ev.requestMethod} {ev.requestUrl}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Clearance / Role Switcher */}
        <div className="relative">
          <button
            onClick={() => setRoleDropdownOpen(!roleDropdownOpen)}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs text-slate-200 transition"
          >
            <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
            <div className="text-left font-mono">
              <div className="text-[10px] text-slate-500 leading-none">CLEARANCE</div>
              <div className="font-bold text-cyan-400 leading-tight">{userRole}</div>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-500" />
          </button>

          {roleDropdownOpen && (
            <div className="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-2 z-50 text-xs">
              <div className="px-2 py-1 text-[10px] font-mono text-slate-500 border-b border-slate-800 mb-1">
                SWITCH SIMULATED RBAC ROLE
              </div>
              {roles.map(r => (
                <button
                  key={r}
                  onClick={() => {
                    onRoleChange(r);
                    setRoleDropdownOpen(false);
                  }}
                  className={`w-full text-left px-2.5 py-2 rounded-lg font-mono transition flex items-center justify-between ${
                    userRole === r ? 'bg-cyan-500/20 text-cyan-300 font-bold' : 'text-slate-400 hover:bg-slate-800 hover:text-white'
                  }`}
                >
                  <span>{r}</span>
                  {userRole === r && <span className="text-[10px] text-cyan-400">ACTIVE</span>}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
