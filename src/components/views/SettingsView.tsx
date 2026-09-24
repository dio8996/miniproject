import React, { useState } from 'react';
import { Sliders, ShieldCheck, Key, RefreshCw, Save, CheckCircle2 } from 'lucide-react';
import { UserRole } from '../../types/security';

interface SettingsViewProps {
  userRole: UserRole;
  onResetDemo: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ userRole, onResetDemo }) => {
  const [autoBlockThreshold, setAutoBlockThreshold] = useState(80);
  const [velocityThreshold, setVelocityThreshold] = useState(25);
  const [blockDuration, setBlockDuration] = useState(30);
  const [entropyThreshold, setEntropyThreshold] = useState(4.5);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const isAdmin = userRole === 'ADMIN';

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 3000);
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto font-mono text-xs">
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
          <Sliders className="w-5 h-5 text-cyan-400" />
          ZeroAttack Engine Configuration & Defense Thresholds
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Tune algorithmic sensitivity, statistical anomaly boundaries, and cryptographic cipher parameters
        </p>
      </div>

      {savedSuccess && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-800 rounded-xl text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>Engine configuration successfully synchronized and applied to detection pipeline.</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Detection Thresholds */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-sm font-semibold text-white">Automated Mitigation & Sensitivity</h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 mb-1">
                Auto-Block Risk Score Threshold (0 - 100)
              </label>
              <input
                type="number"
                min={50}
                max={100}
                value={autoBlockThreshold}
                onChange={(e) => setAutoBlockThreshold(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Scores $\ge$ this value trigger automatic host quarantine in firewall
              </span>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">
                Quarantine Duration (Minutes)
              </label>
              <input
                type="number"
                min={5}
                max={1440}
                value={blockDuration}
                onChange={(e) => setBlockDuration(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Duration hostile IP remains banned before auto-expiry
              </span>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">
                Anomaly Velocity Trigger (req/min)
              </label>
              <input
                type="number"
                min={10}
                max={100}
                value={velocityThreshold}
                onChange={(e) => setVelocityThreshold(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Z-score sliding window velocity anomaly threshold
              </span>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">
                Shannon Entropy Cutoff (bits/char)
              </label>
              <input
                type="number"
                step="0.1"
                min={2.0}
                max={8.0}
                value={entropyThreshold}
                onChange={(e) => setEntropyThreshold(Number(e.target.value))}
                disabled={!isAdmin}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white disabled:opacity-50"
              />
              <span className="text-[10px] text-slate-500 mt-1 block">
                Detects obfuscated shellcode and encoded payloads
              </span>
            </div>
          </div>
        </div>

        {/* Cryptography Config */}
        <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            Payload Encryption Cryptosystem (AES-256-GCM)
          </h3>
          <div className="grid grid-cols-2 gap-4 text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px]">CIPHER ALGORITHM:</span>
              <span className="text-white font-bold">AES-256-GCM (Authenticated Encryption)</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">AUTHENTICATION TAG SIZE:</span>
              <span className="text-white font-bold">128-bit Poly1305 / GMAC Tag</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">INITIALIZATION VECTOR:</span>
              <span className="text-white font-bold">96-bit Unique Nonce Per Record</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">KEY STORAGE REPOSITORY:</span>
              <span className="text-white font-bold">Hardware HSM / ZeroAttack KeyStore</span>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={onResetDemo}
            className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-lg border border-slate-700 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Demo Baseline Data</span>
          </button>

          {isAdmin && (
            <button
              type="submit"
              className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 font-bold text-white rounded-lg transition"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Apply Configuration</span>
            </button>
          )}
        </div>
      </form>
    </div>
  );
};
