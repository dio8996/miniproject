import React from 'react';
import { History, Shield, CheckCircle2 } from 'lucide-react';
import { AuditLogEntry } from '../../types/security';

interface AuditLogsViewProps {
  logs: AuditLogEntry[];
}

export const AuditLogsView: React.FC<AuditLogsViewProps> = ({ logs }) => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
          <History className="w-5 h-5 text-cyan-400" />
          Immutable Security & Compliance Audit Log
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Chronological record of administrative operations, rule modifications, IP quarantines, and forensic access
        </p>
      </div>

      {/* Logs Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5">Operator</th>
                <th className="p-3.5">Action Code</th>
                <th className="p-3.5">Target</th>
                <th className="p-3.5">Origin IP</th>
                <th className="p-3.5">Operation Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/40 transition">
                  <td className="p-3.5 text-slate-400 whitespace-nowrap">
                    {log.timestamp}
                  </td>
                  <td className="p-3.5 font-bold text-cyan-300">
                    {log.username}
                  </td>
                  <td className="p-3.5">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-950 border border-slate-800 text-slate-200">
                      {log.action}
                    </span>
                  </td>
                  <td className="p-3.5 text-slate-300 font-semibold">
                    {log.target}
                  </td>
                  <td className="p-3.5 text-slate-400">
                    {log.ipAddress}
                  </td>
                  <td className="p-3.5 text-slate-300">
                    {log.details}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
