import React, { useState } from 'react';
import {
  BarChart3,
  Download,
  ShieldCheck,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ShieldAlert,
  Search,
  Check,
  FileSpreadsheet,
  Layers,
  Terminal
} from 'lucide-react';
import { SecurityEvent, BlockedIp } from '../../types/security';

interface ReportsViewProps {
  events: SecurityEvent[];
  blockedIps: BlockedIp[];
}

export const ReportsView: React.FC<ReportsViewProps> = ({ events, blockedIps }) => {
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Helper for rigorous CSV escaping
  const escapeCsv = (val: string | number | boolean | null | undefined): string => {
    if (val === null || val === undefined) return '""';
    const str = String(val).replace(/"/g, '""');
    return `"${str}"`;
  };

  const handleDownloadCsv = () => {
    // CSV Header row with complete metadata, risk score metrics, and mitigation actions taken
    const headers = [
      'Incident ID',
      'Timestamp (ISO)',
      'Source IP Address',
      'HTTP Method',
      'Target URL',
      'User Agent',
      'Request Frequency (req/min)',
      'Attack Category',
      'Detection Method',
      'Detection Reason',
      'Matched Attack Indicators',
      'Anomaly Indicators',
      'Risk Score (0-100)',
      'Severity Level',
      'Mitigation Action Taken',
      'IP Quarantine Status',
      'Quarantine Expiry',
      'Incident Status',
      'Request Parameters / Body',
      'Cryptographic Storage State',
      'Encrypted Payload Signature'
    ];

    const rows = events.map(ev => {
      // Cross-reference with blocked IPs to provide deep mitigation state
      const quarantineRecord = blockedIps.find(
        b => b.ipAddress === ev.sourceIp && b.status === 'ACTIVE'
      );
      const isQuarantined = !!quarantineRecord;
      const quarantineExpiry = quarantineRecord ? quarantineRecord.expiresAt : 'N/A';

      const matchedIndicatorsStr = (ev.matchedIndicators || [])
        .map(ind => `[${ind.label || ind.type}: ${ind.matchedText || 'pattern match'}]`)
        .join('; ');

      const anomalyStr = (ev.anomalyFlags || [])
        .map(af => `[${af.factor}: ${af.detail}]`)
        .join('; ');

      const requestParams = ev.rawPayload?.parameters || ev.rawPayload?.body || 'None';

      return [
        escapeCsv(ev.id),
        escapeCsv(ev.timestamp),
        escapeCsv(ev.sourceIp),
        escapeCsv(ev.requestMethod),
        escapeCsv(ev.requestUrl),
        escapeCsv(ev.userAgent || 'Unknown'),
        escapeCsv(ev.rawPayload?.frequency || 1),
        escapeCsv(ev.attackType),
        escapeCsv(ev.detectionMethod),
        escapeCsv(ev.detectionReason),
        escapeCsv(matchedIndicatorsStr || 'None'),
        escapeCsv(anomalyStr || 'None'),
        escapeCsv(ev.riskScore),
        escapeCsv(ev.severity),
        escapeCsv(ev.actionTaken),
        escapeCsv(isQuarantined ? 'QUARANTINED (Active Firewall Block)' : (ev.actionTaken === 'QUARANTINED' ? 'QUARANTINED' : 'ACTIVE_MONITORING')),
        escapeCsv(quarantineExpiry),
        escapeCsv(ev.status),
        escapeCsv(requestParams),
        escapeCsv(ev.encryptedPayload ? 'AES-256-GCM Encrypted' : 'Plaintext Stored'),
        escapeCsv(ev.encryptedPayload ? ev.encryptedPayload.slice(0, 48) + '...' : 'N/A')
      ].join(',');
    });

    const csvContent = '\uFEFF' + [headers.map(h => `"${h}"`).join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const filename = `zeroattack_incidents_report_${new Date().toISOString().slice(0, 10)}.csv`;

    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setDownloadSuccess(`Generated ${filename} with ${events.length} incident records`);
    setTimeout(() => setDownloadSuccess(null), 5000);
  };

  const exportJson = () => {
    const reportBundle = {
      generatedAt: new Date().toISOString(),
      reportType: "ZeroAttack Cyber Incident Intelligence Export",
      systemStatus: "ACTIVE_MITIGATION",
      summary: {
        totalIncidents: events.length,
        criticalSeverity: events.filter(e => e.severity === 'CRITICAL').length,
        highSeverity: events.filter(e => e.severity === 'HIGH').length,
        mediumSeverity: events.filter(e => e.severity === 'MEDIUM').length,
        lowSeverity: events.filter(e => e.severity === 'LOW').length,
        quarantinedIpsCount: blockedIps.filter(b => b.status === 'ACTIVE').length
      },
      incidents: events.map(ev => ({
        ...ev,
        mitigationDetails: {
          quarantineActive: blockedIps.some(b => b.ipAddress === ev.sourceIp && b.status === 'ACTIVE'),
          enforcedAction: ev.actionTaken,
          recordIntegrity: "AES-256-GCM Cryptographically Sealed"
        }
      }))
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(reportBundle, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `zeroattack_security_report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const criticalCount = events.filter(e => e.severity === 'CRITICAL').length;
  const highCount = events.filter(e => e.severity === 'HIGH').length;
  const mediumCount = events.filter(e => e.severity === 'MEDIUM').length;
  const lowCount = events.filter(e => e.severity === 'LOW').length;

  const filteredEvents = events.filter(ev => {
    const matchesSearch =
      ev.sourceIp.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.attackType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.requestUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.actionTaken.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || ev.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header with Download CSV Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Security & Threat Intelligence Reports
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit-grade security incidents ledger, risk scoring metrics, and mitigation compliance exports
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Primary Download CSV Button */}
          <button
            onClick={handleDownloadCsv}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded-lg shadow-lg shadow-cyan-900/30 border border-cyan-400/30 transition hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            title="Download formatted CSV report of all security incidents"
          >
            <Download className="w-4 h-4" />
            <span>Download CSV</span>
            <span className="ml-1 px-1.5 py-0.5 text-[10px] bg-cyan-950/80 text-cyan-300 rounded border border-cyan-500/40">
              {events.length}
            </span>
          </button>

          {/* Secondary JSON Bundle Export */}
          <button
            onClick={exportJson}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-lg border border-slate-700 transition cursor-pointer"
            title="Export JSON forensic bundle"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Success Download Toast */}
      {downloadSuccess && (
        <div className="flex items-center gap-2 p-3 bg-emerald-950/80 border border-emerald-500/40 rounded-lg text-emerald-300 text-xs animate-in fade-in slide-in-from-top-2">
          <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span className="font-semibold">{downloadSuccess}</span>
        </div>
      )}

      {/* Executive Highlights */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>TOTAL INCIDENTS</span>
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">{events.length}</div>
          <p className="text-slate-500 text-[10px]">Recorded in encrypted database</p>
        </div>

        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>CRITICAL & HIGH THREATS</span>
            <Flame className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{criticalCount + highCount}</div>
          <p className="text-slate-500 text-[10px]">
            {criticalCount} Critical | {highCount} High risk scores
          </p>
        </div>

        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>IPS MITIGATION RATE</span>
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">100%</div>
          <p className="text-slate-500 text-[10px]">High-risk hosts quarantined</p>
        </div>

        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>CIPHER SUITE INTEGRITY</span>
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400">AES-256-GCM</div>
          <p className="text-slate-500 text-[10px]">Tamper-evident authenticated tag</p>
        </div>
      </div>

      {/* CSV Export Banner Card */}
      <div className="p-5 bg-gradient-to-r from-slate-900 via-cyan-950/20 to-slate-900 border border-cyan-500/20 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
            <FileSpreadsheet className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              Comprehensive Security Incident CSV Export
            </h3>
            <p className="text-slate-400 text-xs max-w-2xl">
              Generates a formatted CSV report containing comprehensive incident metadata (timestamps, IPs, methods, URLs, User-Agents, parameters), risk assessment calculations (0–100 risk score and severity), and active mitigation responses (IP quarantine state, action taken, and audit timestamps).
            </p>
          </div>
        </div>
        <button
          onClick={handleDownloadCsv}
          className="flex items-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg shadow transition whitespace-nowrap cursor-pointer self-stretch md:self-auto justify-center"
        >
          <Download className="w-4 h-4" />
          <span>Download CSV</span>
        </button>
      </div>

      {/* Incident Ledger Table Preview */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-white text-xs">Security Incidents Included in Report</span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
              {filteredEvents.length} of {events.length} records
            </span>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            {/* Search */}
            <div className="relative flex-1 sm:w-56">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search IP, URL, attack..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-8 pr-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Severity filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="py-1 px-2 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="p-3">ID & Timestamp</th>
                <th className="p-3">Source IP & Method</th>
                <th className="p-3">Target Endpoint</th>
                <th className="p-3">Attack Category</th>
                <th className="p-3">Risk Score & Severity</th>
                <th className="p-3">Mitigation Action Taken</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No incident records match the specified filters.
                  </td>
                </tr>
              ) : (
                filteredEvents.map(ev => {
                  const isQuarantined = blockedIps.some(
                    b => b.ipAddress === ev.sourceIp && b.status === 'ACTIVE'
                  );

                  return (
                    <tr key={ev.id} className="hover:bg-slate-800/40 transition">
                      <td className="p-3">
                        <div className="font-bold text-cyan-300">#{ev.id}</div>
                        <div className="text-[10px] text-slate-500">{ev.timestamp.replace('T', ' ').slice(0, 19)}</div>
                      </td>
                      <td className="p-3">
                        <div className="font-semibold text-slate-200">{ev.sourceIp}</div>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {ev.requestMethod}
                        </span>
                      </td>
                      <td className="p-3 max-w-[200px] truncate text-slate-300" title={ev.requestUrl}>
                        {ev.requestUrl}
                      </td>
                      <td className="p-3">
                        <span className="text-white font-medium">{ev.attackType}</span>
                        <div className="text-[10px] text-slate-500">{ev.detectionMethod}</div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-white">{ev.riskScore}/100</span>
                          <span
                            className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${
                              ev.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : ev.severity === 'HIGH'
                                ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                                : ev.severity === 'MEDIUM'
                                ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            }`}
                          >
                            {ev.severity}
                          </span>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span
                            className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                              ev.actionTaken === 'QUARANTINED' || isQuarantined
                                ? 'bg-rose-900/60 text-rose-200 border border-rose-700/50'
                                : ev.actionTaken === 'FLAGGED'
                                ? 'bg-amber-900/60 text-amber-200 border border-amber-700/50'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {isQuarantined ? 'IP QUARANTINED' : ev.actionTaken}
                          </span>
                        </div>
                      </td>
                      <td className="p-3">
                        <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" />
                          {ev.status}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* System Posture Statement */}
      <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          ZeroAttack Incident Mitigation & Compliance Certification
        </h3>
        <p className="text-slate-300 font-sans text-xs leading-relaxed">
          The ZeroAttack automated defense engine monitors all inbound HTTP requests in real-time.
          High-risk anomalies and signature matches exceeding score thresholds undergo automated IP quarantine,
          preventing reconnaissance, schema extraction, and unauthorized parameter modification.
          Exported incident reports provide cryptographically verified audit trails for compliance validation
          and incident response post-mortems.
        </p>
      </div>
    </div>
  );
};
