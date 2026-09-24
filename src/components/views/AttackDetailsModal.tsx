import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  KeyRound,
  FileCode2,
  Server,
  Terminal,
  Activity,
  UserCheck
} from 'lucide-react';
import { SecurityEvent, UserRole } from '../../types/security';

interface AttackDetailsModalProps {
  event: SecurityEvent;
  userRole: UserRole;
  onClose: () => void;
  onUpdateStatus: (id: number, status: SecurityEvent['status']) => void;
}

export const AttackDetailsModal: React.FC<AttackDetailsModalProps> = ({
  event,
  userRole,
  onClose,
  onUpdateStatus
}) => {
  const [isDecrypted, setIsDecrypted] = useState(false);
  const [decryptionError, setDecryptionError] = useState<string | null>(null);

  const canDecrypt = userRole === 'ADMIN' || userRole === 'SECURITY ANALYST';

  const handleDecrypt = () => {
    if (!canDecrypt) {
      setDecryptionError(`Clearance Violation: Role "${userRole}" lacks cryptographic decryption permission. Switch clearance to ADMIN or SECURITY ANALYST.`);
      return;
    }
    setDecryptionError(null);
    setIsDecrypted(true);
  };

  const getSeverityColor = (sev: string) => {
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
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col my-8 font-mono text-xs">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-lg bg-cyan-950/80 border border-cyan-800 text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">Forensic Incident Report #{event.id}</h3>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityColor(event.severity)}`}>
                  {event.severity}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Timestamp: {event.timestamp} &bull; Actor: {event.sourceIp}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] block">COMPOSITE RISK</span>
              <div className="text-2xl font-bold text-rose-400 mt-1">{event.riskScore} / 100</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] block">ATTACK CLASSIFICATION</span>
              <div className="text-sm font-bold text-cyan-300 mt-1">{event.attackType}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] block">DETECTION ENGINE</span>
              <div className="text-sm font-bold text-white mt-1">{event.detectionMethod}</div>
            </div>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
              <span className="text-slate-500 text-[10px] block">MITIGATION APPLIED</span>
              <div className="text-sm font-bold text-orange-400 mt-1">{event.actionTaken}</div>
            </div>
          </div>

          {/* Raw HTTP Packet Inspection Details */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Raw Inspected HTTP Request Packet
              </span>
              <span className="text-[10px] text-slate-500">{event.requestMethod} {event.requestUrl}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
              <div>
                <span className="text-slate-500 block text-[10px]">TARGET URL:</span>
                <span className="text-white font-mono">{event.requestUrl}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">SOURCE IP:</span>
                <span className="text-white font-mono">{event.sourceIp}</span>
              </div>
              <div className="sm:col-span-2">
                <span className="text-slate-500 block text-[10px]">USER-AGENT HEADER:</span>
                <span className="text-slate-300 font-mono break-all">{event.userAgent}</span>
              </div>
              <div className="sm:col-span-2">
                <span className="text-slate-500 block text-[10px]">QUERY / PAYLOAD PARAMETERS:</span>
                <div className="mt-1 p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 break-all">
                  {event.rawPayload.parameters || 'None'}
                </div>
              </div>
            </div>
          </div>

          {/* Detection Logic & Evidence */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
            <span className="font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              Engine Rationale & Indicator Matches
            </span>
            <p className="text-slate-300 leading-relaxed">{event.detectionReason}</p>

            {event.matchedIndicators.length > 0 && (
              <div className="mt-3 space-y-2">
                <span className="text-slate-400 text-[10px] font-semibold block">RULE SIGNATURE EVIDENCE:</span>
                {event.matchedIndicators.map((ind, i) => (
                  <div key={i} className="p-2 bg-slate-900/90 border border-rose-950/60 rounded flex justify-between items-center">
                    <div>
                      <span className="text-rose-300 font-bold">{ind.label}</span>
                      <span className="text-slate-400 block text-[10px]">Matched token: <code className="text-slate-200">"{ind.matchedText}"</code></span>
                    </div>
                    <span className="text-rose-400 font-bold">+{ind.weight} pts</span>
                  </div>
                ))}
              </div>
            )}

            {event.anomalyFlags.length > 0 && (
              <div className="mt-3 space-y-2">
                <span className="text-slate-400 text-[10px] font-semibold block">STATISTICAL ANOMALY EVIDENCE:</span>
                {event.anomalyFlags.map((flag, i) => (
                  <div key={i} className="p-2 bg-slate-900/90 border border-amber-950/60 rounded flex justify-between items-center">
                    <div>
                      <span className="text-amber-300 font-bold">{flag.factor}</span>
                      <span className="text-slate-400 block text-[10px]">{flag.detail}</span>
                    </div>
                    <span className="text-amber-400 font-bold">+{flag.severityContrib} pts</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Cryptographic Encryption & Authorized Decryption Section */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2 text-white font-semibold">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Encrypted Security Record & Forensic Decryption (AES-256-GCM)</span>
              </div>
              <span className="text-[10px] text-cyan-400/80 font-mono">CONFIDENTIAL STORAGE</span>
            </div>

            {/* Architecture Flow Banner */}
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
              <span className="text-slate-300 font-semibold">Security Flow:</span>
              <div className="flex items-center gap-2 text-cyan-400 font-mono text-[10px]">
                <span>Plain Packet</span>
                <span>&rarr;</span>
                <span className="text-amber-300">AES-256-GCM Cipher</span>
                <span>&rarr;</span>
                <span className="text-rose-300">Encrypted DB Record</span>
                <span>&rarr;</span>
                <span className="text-emerald-300">Authorized Decryption</span>
              </div>
            </div>

            {/* Ciphertext Box */}
            <div>
              <span className="text-slate-500 text-[10px] block mb-1">
                ENCRYPTED DATABASE CIPHERTEXT (Stored in MySQL `security_events` table):
              </span>
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300/90 break-all font-mono text-[11px]">
                {event.encryptedPayload}
              </div>
            </div>

            {/* Decryption Action */}
            <div className="pt-2">
              {!isDecrypted ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <button
                      onClick={handleDecrypt}
                      className="flex items-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 font-bold text-white rounded-lg transition"
                    >
                      <KeyRound className="w-4 h-4" />
                      <span>Perform Authorized Forensic Decryption</span>
                    </button>
                    <span className="text-[11px] text-slate-400">
                      Current Clearance: <strong className="text-cyan-400">{userRole}</strong>
                    </span>
                  </div>

                  {decryptionError && (
                    <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-[11px] flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400" />
                      <span>{decryptionError}</span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3.5 bg-slate-900 border border-emerald-900/60 rounded-xl space-y-2">
                  <div className="flex items-center justify-between text-emerald-400 font-semibold text-xs border-b border-slate-800 pb-2">
                    <span className="flex items-center gap-1.5">
                      <Unlock className="w-4 h-4" />
                      Decrypted Plaintext Forensic Packet (Clearance: {userRole})
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">NONCE & MAC VERIFIED</span>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded text-slate-200 overflow-x-auto text-[11px] whitespace-pre-wrap leading-relaxed">
                    {event.decryptedPlaintext || JSON.stringify(event.rawPayload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Incident Status Workflow */}
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex items-center justify-between">
            <div>
              <span className="text-slate-500 text-[10px] block">INCIDENT LIFECYCLE STATUS:</span>
              <span className="text-white font-bold text-sm">{event.status}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400 text-xs">Update Status:</span>
              {(['DETECTED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => onUpdateStatus(event.id, st)}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold transition ${
                    event.status === st
                      ? 'bg-cyan-500 text-slate-950'
                      : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
          >
            Close Forensics Window
          </button>
        </div>
      </div>
    </div>
  );
};
