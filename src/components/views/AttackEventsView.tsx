import React, { useState } from 'react';
import { Search, Filter, ShieldAlert, ShieldCheck, Eye, Terminal } from 'lucide-react';
import { SecurityEvent, SeverityLevel, AttackCategory, EventStatus } from '../../types/security';

interface AttackEventsViewProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
  onNavigateToMonitor: () => void;
}

export const AttackEventsView: React.FC<AttackEventsViewProps> = ({
  events,
  onSelectEvent,
  onNavigateToMonitor
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredEvents = events.filter((ev) => {
    const matchesSearch =
      ev.sourceIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.requestUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.attackType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.detectionReason.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || ev.severity === severityFilter;
    const matchesType = typeFilter === 'ALL' || ev.attackType === typeFilter;
    const matchesStatus = statusFilter === 'ALL' || ev.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesType && matchesStatus;
  });

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/70 border border-rose-800/80';
      case 'HIGH':
        return 'text-orange-400 bg-orange-950/70 border border-orange-800/80';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-950/70 border border-amber-800/80';
      default:
        return 'text-emerald-400 bg-emerald-950/70 border border-emerald-800/80';
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            Security Attack Events & Incident Forensic Feed
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Chronological audit of suspicious requests, rule violations, and behavioral anomaly vectors
          </p>
        </div>
        <button
          onClick={onNavigateToMonitor}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-cyan-300 bg-cyan-950/80 border border-cyan-800 rounded-lg hover:bg-cyan-900 transition font-mono"
        >
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>+ Simulate Attack</span>
        </button>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl space-y-3 font-mono text-xs">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by Source IP, URL, attack vector, or reason..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-white focus:border-cyan-500 outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-slate-300 focus:border-cyan-500 outline-none"
            >
              <option value="ALL">Severity: ALL</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>

            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-slate-300 focus:border-cyan-500 outline-none"
            >
              <option value="ALL">Vector: ALL</option>
              <option value="SQL Injection">SQL Injection</option>
              <option value="Cross-Site Scripting (XSS)">XSS</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Parameter Tampering">Parameter Tampering</option>
              <option value="Anomaly Detection">Anomaly Detection</option>
              <option value="Normal Request">Normal Request</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-slate-300 focus:border-cyan-500 outline-none"
            >
              <option value="ALL">Status: ALL</option>
              <option value="DETECTED">DETECTED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="MITIGATED">MITIGATED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-slate-400 text-[11px] pt-1">
          <span>Showing {filteredEvents.length} of {events.length} security incidents</span>
          {(searchTerm || severityFilter !== 'ALL' || typeFilter !== 'ALL' || statusFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSearchTerm('');
                setSeverityFilter('ALL');
                setTypeFilter('ALL');
                setStatusFilter('ALL');
              }}
              className="text-cyan-400 hover:underline"
            >
              Clear Filters
            </button>
          )}
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-slate-900/80 border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">ID / Time</th>
                <th className="p-3.5">Source IP</th>
                <th className="p-3.5">Target Endpoint</th>
                <th className="p-3.5">Attack Classification</th>
                <th className="p-3.5">Engine</th>
                <th className="p-3.5 text-right">Risk</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Action</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={10} className="p-8 text-center text-slate-500">
                    No matching attack events found.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => onSelectEvent(ev)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="p-3.5 text-slate-400">
                      <div>#{ev.id}</div>
                      <div className="text-[10px] text-slate-500">{ev.timestamp.split(' ')[1] || ev.timestamp}</div>
                    </td>
                    <td className="p-3.5 font-bold text-white">
                      {ev.sourceIp}
                    </td>
                    <td className="p-3.5 max-w-xs truncate text-slate-300">
                      <span className="text-[10px] text-cyan-400 mr-1.5">{ev.requestMethod}</span>
                      <span title={ev.requestUrl}>{ev.requestUrl}</span>
                    </td>
                    <td className="p-3.5 text-cyan-300 font-semibold">
                      {ev.attackType}
                    </td>
                    <td className="p-3.5 text-slate-400 text-[11px]">
                      {ev.detectionMethod}
                    </td>
                    <td className="p-3.5 text-right font-bold text-white tabular-nums">
                      <span className={
                        ev.riskScore >= 80 ? 'text-rose-400' : ev.riskScore >= 60 ? 'text-orange-400' : 'text-slate-300'
                      }>
                        {ev.riskScore}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getSeverityBadge(ev.severity)}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="p-3.5 font-semibold">
                      <span className={
                        ev.actionTaken === 'BLOCKED'
                          ? 'text-rose-400'
                          : ev.actionTaken === 'QUARANTINED'
                          ? 'text-orange-400'
                          : ev.actionTaken === 'FLAGGED'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }>
                        {ev.actionTaken}
                      </span>
                    </td>
                    <td className="p-3.5 text-slate-400 text-[11px]">
                      {ev.status}
                    </td>
                    <td className="p-3.5 text-right">
                      <button className="text-cyan-400 hover:text-cyan-300 p-1 rounded hover:bg-slate-800">
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
