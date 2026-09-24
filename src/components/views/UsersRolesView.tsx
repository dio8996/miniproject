import React from 'react';
import { Users, Shield, Check, X, UserCheck } from 'lucide-react';
import { User, UserRole } from '../../types/security';

interface UsersRolesViewProps {
  users: User[];
  currentRole: UserRole;
  onSelectRole: (role: UserRole) => void;
}

export const UsersRolesView: React.FC<UsersRolesViewProps> = ({
  users,
  currentRole,
  onSelectRole
}) => {
  const permissions = [
    { capability: 'View Real-Time SOC Dashboard & Charts', viewer: true, analyst: true, admin: true },
    { capability: 'Simulate & Inspect Live HTTP Requests', viewer: true, analyst: true, admin: true },
    { capability: 'Inspect Incident Forensics & Raw Packets', viewer: true, analyst: true, admin: true },
    { capability: 'Perform Authorized Payload Decryption (AES-256-GCM)', viewer: false, analyst: true, admin: true },
    { capability: 'Quarantine & Blacklist Host IPs Manually', viewer: false, analyst: false, admin: true },
    { capability: 'Unblock / Whitelist Firewalled IPs', viewer: false, analyst: false, admin: true },
    { capability: 'Deploy, Edit & Delete Detection Signatures', viewer: false, analyst: false, admin: true },
    { capability: 'Configure System Detection Thresholds', viewer: false, analyst: false, admin: true },
    { capability: 'Manage User Clearances & Credentials', viewer: false, analyst: false, admin: true }
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
          <Users className="w-5 h-5 text-cyan-400" />
          Role-Based Access Control (RBAC) & Clearance Matrix
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Manage system clearance tiers: ADMIN, SECURITY ANALYST, and VIEWER roles
        </p>
      </div>

      {/* Role Cards with Quick Switch */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {(['ADMIN', 'SECURITY ANALYST', 'VIEWER'] as UserRole[]).map((r) => {
          const isCurrent = currentRole === r;
          return (
            <div
              key={r}
              className={`p-5 rounded-xl border transition flex flex-col justify-between ${
                isCurrent
                  ? 'bg-slate-900 border-cyan-500 shadow-lg shadow-cyan-950/40'
                  : 'bg-slate-900/80 border-slate-800'
              }`}
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    r === 'ADMIN' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    r === 'SECURITY ANALYST' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                    'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {r}
                  </span>
                  {isCurrent && (
                    <span className="text-[10px] text-cyan-400 font-bold flex items-center gap-1">
                      <UserCheck className="w-3.5 h-3.5" />
                      ACTIVE CLEARANCE
                    </span>
                  )}
                </div>

                <div className="mt-3 text-slate-300 font-sans text-xs leading-relaxed">
                  {r === 'ADMIN' && 'Full executive authority over IPS firewalls, custom rule deployment, payload decryption, and compliance audits.'}
                  {r === 'SECURITY ANALYST' && 'Operational threat triage, forensic incident analysis, authorized record decryption, and status updates.'}
                  {r === 'VIEWER' && 'Read-only visibility for executive stakeholder dashboards, threat velocity charts, and compliance reports.'}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <button
                  onClick={() => onSelectRole(r)}
                  disabled={isCurrent}
                  className={`w-full py-2 rounded-lg font-bold transition text-xs ${
                    isCurrent
                      ? 'bg-cyan-500/20 text-cyan-400 cursor-default'
                      : 'bg-slate-800 hover:bg-slate-700 text-white'
                  }`}
                >
                  {isCurrent ? 'Current Session Role' : `Switch Clearance to ${r}`}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Permissions Matrix */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <h3 className="text-sm font-semibold text-white">RBAC Capability Entitlements Matrix</h3>
          <p className="text-[11px] text-slate-400">Granular permissions mapping for security audit compliance</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Permission / Action Capability</th>
                <th className="p-3.5 text-center">VIEWER</th>
                <th className="p-3.5 text-center">SECURITY ANALYST</th>
                <th className="p-3.5 text-center">ADMIN</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {permissions.map((p, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40 transition">
                  <td className="p-3.5 text-slate-300 font-sans text-xs font-medium">
                    {p.capability}
                  </td>
                  <td className="p-3.5 text-center">
                    {p.viewer ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-slate-600 mx-auto" />}
                  </td>
                  <td className="p-3.5 text-center">
                    {p.analyst ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-slate-600 mx-auto" />}
                  </td>
                  <td className="p-3.5 text-center">
                    {p.admin ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-slate-600 mx-auto" />}
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
