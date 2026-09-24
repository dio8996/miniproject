import React, { useState } from 'react';
import { Ban, ShieldCheck, ShieldAlert, Plus, RefreshCw, Lock } from 'lucide-react';
import { BlockedIp, UserRole } from '../../types/security';

interface IpManagementViewProps {
  blockedIps: BlockedIp[];
  userRole: UserRole;
  onBlockIp: (ip: string, reason: string, score: number, durationMins: number) => void;
  onUnblockIp: (ip: string) => void;
}

export const IpManagementView: React.FC<IpManagementViewProps> = ({
  blockedIps,
  userRole,
  onBlockIp,
  onUnblockIp
}) => {
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [newIp, setNewIp] = useState('');
  const [reason, setReason] = useState('Manual Administrative Quarantine');
  const [score, setScore] = useState(85);
  const [duration, setDuration] = useState(60);

  const isAdmin = userRole === 'ADMIN';

  const handleManualBlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    onBlockIp(newIp.trim(), reason, score, duration);
    setNewIp('');
    setShowBlockModal(false);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Ban className="w-5 h-5 text-rose-500" />
            Quarantined IP Addresses & Firewall Rules
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated IPS containment policies and manual host firewalls
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isAdmin ? (
            <button
              onClick={() => setShowBlockModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 font-bold text-white rounded-lg transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Quarantine Host IP</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 text-slate-500 rounded-lg">
              <Lock className="w-3.5 h-3.5" />
              <span>Admin Clearance Required to Block/Unblock</span>
            </div>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <span className="text-slate-400 text-[10px]">TOTAL BLOCKED HOSTS</span>
          <div className="text-2xl font-bold text-rose-400 mt-1">
            {blockedIps.filter(b => b.status === 'ACTIVE').length} Active
          </div>
          <p className="text-slate-500 text-[10px] mt-1">Automated IPS drop rules active</p>
        </div>
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <span className="text-slate-400 text-[10px]">AUTO-DEFENSE THRESHOLD</span>
          <div className="text-2xl font-bold text-cyan-400 mt-1">Score $\ge$ 80</div>
          <p className="text-slate-500 text-[10px] mt-1">Instant 30m temporary blacklist</p>
        </div>
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <span className="text-slate-400 text-[10px]">CURRENT CLEARANCE</span>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{userRole}</div>
          <p className="text-slate-500 text-[10px] mt-1">{isAdmin ? 'Full firewall control' : 'Read-only access'}</p>
        </div>
      </div>

      {/* Blocked IP Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Source IP Address</th>
                <th className="p-3.5">Quarantine Justification</th>
                <th className="p-3.5 text-right">Risk Score</th>
                <th className="p-3.5">Quarantined At</th>
                <th className="p-3.5">Expires At</th>
                <th className="p-3.5">Enforced By</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500">
                    No blocked IPs on record.
                  </td>
                </tr>
              ) : (
                blockedIps.map((b) => (
                  <tr key={b.id} className="hover:bg-slate-800/40 transition">
                    <td className="p-3.5 text-white font-bold">
                      {b.ipAddress}
                    </td>
                    <td className="p-3.5 text-slate-300 max-w-sm">
                      {b.reason}
                    </td>
                    <td className="p-3.5 text-right font-bold text-rose-400">
                      {b.riskScore}/100
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {b.blockedAt}
                    </td>
                    <td className="p-3.5 text-slate-400">
                      {b.expiresAt}
                    </td>
                    <td className="p-3.5 text-cyan-300">
                      {b.blockedBy}
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        b.status === 'ACTIVE'
                          ? 'bg-rose-950/70 text-rose-400 border-rose-800'
                          : b.status === 'WHITELISTED'
                          ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {b.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-right">
                      {b.status === 'ACTIVE' ? (
                        isAdmin ? (
                          <button
                            onClick={() => onUnblockIp(b.ipAddress)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-semibold border border-slate-700 transition"
                          >
                            Unblock / Whitelist
                          </button>
                        ) : (
                          <span className="text-slate-500 text-[10px]">Restricted</span>
                        )
                      ) : (
                        <span className="text-slate-500 text-[10px]">N/A</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Manual Quarantine Modal */}
      {showBlockModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Ban className="w-4 h-4 text-rose-500" />
                Manual IP Quarantine Order
              </h3>
              <button
                onClick={() => setShowBlockModal(false)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleManualBlock} className="space-y-3">
              <div>
                <label className="block text-slate-400 mb-1">Target Host IP Address</label>
                <input
                  type="text"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="e.g. 198.51.100.99"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-rose-500 outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Incident / Quarantine Justification</label>
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-rose-500 outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Assigned Risk Score</label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={score}
                    onChange={(e) => setScore(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-rose-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Duration (Minutes)</label>
                  <input
                    type="number"
                    min={5}
                    max={1440}
                    value={duration}
                    onChange={(e) => setDuration(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-rose-500 outline-none"
                  />
                </div>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowBlockModal(false)}
                  className="px-3 py-2 bg-slate-800 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 font-bold text-white rounded-lg transition"
                >
                  Enforce Quarantine
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
