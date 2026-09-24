import React, { useState } from 'react';
import { FileCode2, Plus, Trash2, Power, Lock, CheckCircle2, AlertTriangle } from 'lucide-react';
import { DetectionRule, AttackCategory, SeverityLevel, UserRole } from '../../types/security';

interface DetectionRulesViewProps {
  rules: DetectionRule[];
  userRole: UserRole;
  onAddRule: (rule: Omit<DetectionRule, 'id' | 'createdAt'>) => void;
  onToggleRule: (id: number) => void;
  onDeleteRule: (id: number) => void;
}

export const DetectionRulesView: React.FC<DetectionRulesViewProps> = ({
  rules,
  userRole,
  onAddRule,
  onToggleRule,
  onDeleteRule
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [name, setName] = useState('');
  const [attackType, setAttackType] = useState<AttackCategory>('SQL Injection');
  const [pattern, setPattern] = useState('');
  const [targetField, setTargetField] = useState<'ALL' | 'URL' | 'PARAMETERS' | 'HEADERS' | 'BODY'>('ALL');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<SeverityLevel>('CRITICAL');
  const [riskWeight, setRiskWeight] = useState(85);

  const isAdmin = userRole === 'ADMIN';

  const handleAddSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !pattern.trim()) return;

    onAddRule({
      name: name.trim(),
      attackType,
      pattern: pattern.trim(),
      targetField,
      description: description.trim() || 'Custom detection signature',
      severity,
      riskWeight: Number(riskWeight),
      isActive: true
    });

    setName('');
    setPattern('');
    setDescription('');
    setShowAddModal(false);
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/70 border-rose-800';
      case 'HIGH':
        return 'text-orange-400 bg-orange-950/70 border-orange-800';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-950/70 border-amber-800';
      default:
        return 'text-emerald-400 bg-emerald-950/70 border-emerald-800';
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-cyan-400" />
            Detection Rules Engine & Signature Catalog
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure regex signatures, heuristic matching parameters, and risk score weights
          </p>
        </div>
        <div>
          {isAdmin ? (
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 font-bold text-white rounded-lg transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Deploy New Signature</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 text-slate-500 rounded-lg">
              <Lock className="w-3.5 h-3.5" />
              <span>Admin Clearance Required to Manage Rules</span>
            </div>
          )}
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Rule Signature Name</th>
                <th className="p-3.5">Vector</th>
                <th className="p-3.5">Regex Signature Pattern</th>
                <th className="p-3.5">Scope</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5 text-right">Weight</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/40 transition">
                  <td className="p-3.5">
                    <div className="text-white font-bold">{r.name}</div>
                    <div className="text-[10px] text-slate-500 mt-0.5 max-w-xs truncate">{r.description}</div>
                  </td>
                  <td className="p-3.5 text-cyan-300 font-semibold">
                    {r.attackType}
                  </td>
                  <td className="p-3.5 max-w-xs truncate text-slate-300 font-mono">
                    <code className="bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 text-rose-300" title={r.pattern}>
                      {r.pattern}
                    </code>
                  </td>
                  <td className="p-3.5 text-slate-400 text-[11px]">
                    {r.targetField}
                  </td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(r.severity)}`}>
                      {r.severity}
                    </span>
                  </td>
                  <td className="p-3.5 text-right font-bold text-white tabular-nums">
                    +{r.riskWeight} pts
                  </td>
                  <td className="p-3.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      r.isActive ? 'text-emerald-400 bg-emerald-950/50 border border-emerald-800' : 'text-slate-500 bg-slate-900 border border-slate-800'
                    }`}>
                      {r.isActive ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td className="p-3.5 text-right space-x-2">
                    {isAdmin ? (
                      <>
                        <button
                          onClick={() => onToggleRule(r.id)}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded transition"
                          title="Toggle Rule State"
                        >
                          <Power className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onDeleteRule(r.id)}
                          className="px-2 py-1 bg-slate-800 hover:bg-rose-900 text-rose-400 rounded transition"
                          title="Delete Signature"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </>
                    ) : (
                      <span className="text-slate-600 text-[10px]">Read-Only</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deploy Signature Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                Deploy New Detection Signature
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-white"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3">
              <div>
                <label className="block text-slate-400 mb-1">Signature Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. LDAP / NoSQL Injection Pattern"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Attack Category</label>
                  <select
                    value={attackType}
                    onChange={(e) => setAttackType(e.target.value as AttackCategory)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  >
                    <option value="SQL Injection">SQL Injection</option>
                    <option value="Cross-Site Scripting (XSS)">Cross-Site Scripting (XSS)</option>
                    <option value="Brute Force">Brute Force</option>
                    <option value="Parameter Tampering">Parameter Tampering</option>
                    <option value="Anomaly Detection">Anomaly Detection</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Target Inspection Field</label>
                  <select
                    value={targetField}
                    onChange={(e) => setTargetField(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  >
                    <option value="ALL">ALL (URL + Params + Headers)</option>
                    <option value="URL">URL Path Only</option>
                    <option value="PARAMETERS">Query & Body Parameters</option>
                    <option value="HEADERS">Headers & User-Agent</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Regular Expression Pattern</label>
                <input
                  type="text"
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="(?i)(pattern_regex_here)"
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Assigned Severity</label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Risk Weight (Points)</label>
                  <input
                    type="number"
                    min={10}
                    max={100}
                    value={riskWeight}
                    onChange={(e) => setRiskWeight(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description / Threat Intelligence Reference</label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Identifies malicious tokens targeting backend data layer..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-2 bg-slate-800 text-slate-300 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 font-bold text-white rounded-lg transition"
                >
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
