import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import {
  ShieldAlert,
  Activity,
  Ban,
  AlertTriangle,
  ArrowUpRight,
  Flame,
  CheckCircle2
} from 'lucide-react';
import { SecurityEvent, BlockedIp, SystemMetrics } from '../../types/security';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface DashboardViewProps {
  metrics: SystemMetrics;
  events: SecurityEvent[];
  blockedIps: BlockedIp[];
  onSelectEvent: (event: SecurityEvent) => void;
  onNavigateToMonitor: () => void;
  onNavigateToIps: () => void;
  onNavigateToEvents: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  events,
  blockedIps,
  onSelectEvent,
  onNavigateToMonitor,
  onNavigateToIps,
  onNavigateToEvents
}) => {
  // --- 1. Attack Type Distribution Data ---
  const attackCounts: Record<string, number> = {};
  events.forEach(e => {
    if (e.attackType !== 'Normal Request') {
      attackCounts[e.attackType] = (attackCounts[e.attackType] || 0) + 1;
    }
  });

  const doughnutLabels = Object.keys(attackCounts).length > 0
    ? Object.keys(attackCounts)
    : ['SQL Injection', 'Cross-Site Scripting', 'Brute Force', 'Parameter Tampering'];
  
  const doughnutData = Object.keys(attackCounts).length > 0
    ? Object.values(attackCounts)
    : [3, 2, 2, 1];

  const attackTypeChartData = {
    labels: doughnutLabels,
    datasets: [
      {
        data: doughnutData,
        backgroundColor: [
          '#ef4444', // Red (SQLi)
          '#f97316', // Orange (XSS)
          '#a855f7', // Purple (Brute force)
          '#06b6d4', // Cyan (Tampering)
          '#eab308'  // Yellow (Anomaly)
        ],
        borderWidth: 0,
        hoverOffset: 4
      }
    ]
  };

  // --- 2. Severity Distribution Data ---
  const severityCounts = {
    LOW: events.filter(e => e.severity === 'LOW').length,
    MEDIUM: events.filter(e => e.severity === 'MEDIUM').length,
    HIGH: events.filter(e => e.severity === 'HIGH').length,
    CRITICAL: events.filter(e => e.severity === 'CRITICAL').length
  };

  const severityChartData = {
    labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    datasets: [
      {
        label: 'Security Incidents',
        data: [severityCounts.LOW, severityCounts.MEDIUM, severityCounts.HIGH, severityCounts.CRITICAL],
        backgroundColor: ['#10b981', '#eab308', '#f97316', '#ef4444'],
        borderRadius: 4
      }
    ]
  };

  // --- 3. Attacks Over Time Line Chart ---
  const timelineLabels = ['-50m', '-40m', '-30m', '-20m', '-10m', 'Now'];
  const attacksTimelineData = {
    labels: timelineLabels,
    datasets: [
      {
        label: 'Total Requests',
        data: [35, 42, 58, 48, 62, 54],
        borderColor: '#334155',
        backgroundColor: 'rgba(51, 65, 85, 0.1)',
        fill: true,
        tension: 0.35,
        borderWidth: 1.5,
        pointRadius: 2
      },
      {
        label: 'Detected Malicious Incidents',
        data: [2, 4, 9, 5, 12, Math.max(events.length, 7)],
        borderColor: '#06b6d4',
        backgroundColor: 'rgba(6, 182, 212, 0.15)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: '#06b6d4'
      }
    ]
  };

  // --- 4. Suspicious IP Activity Ranking ---
  const ipCounts: Record<string, number> = {};
  events.forEach(e => {
    if (e.attackType !== 'Normal Request') {
      ipCounts[e.sourceIp] = (ipCounts[e.sourceIp] || 0) + 1;
    }
  });
  const sortedIps = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const getSeverityBadge = (sev: string) => {
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
      {/* Real-Time Alert Banner if elevated risk */}
      {metrics.currentRiskLevel.includes('CRITICAL') && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Flame className="w-5 h-5 text-rose-500 animate-pulse" />
            <div>
              <div className="text-sm font-semibold text-rose-300">
                CRITICAL THREAT THRESHOLD REACHED — IPS ACTIVE
              </div>
              <div className="text-xs text-rose-400/80">
                Automated defensive rate-limiting and temporary IP quarantine active on {metrics.blockedIpsCount} host actors.
              </div>
            </div>
          </div>
          <button
            onClick={onNavigateToIps}
            className="text-xs font-mono font-bold text-rose-200 hover:text-white bg-rose-900/60 hover:bg-rose-800 px-3 py-1.5 rounded-lg border border-rose-700/50 transition"
          >
            Review Quarantined IPs &rarr;
          </button>
        </div>
      )}

      {/* Top 5 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Metric 1 */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Requests Inspected</span>
            <Activity className="w-4 h-4 text-slate-500" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-white tabular-nums">
              {metrics.totalRequests.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">HTTP / HTTPS Streams</div>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Detected Attacks</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
              {metrics.detectedAttacks.toLocaleString()}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Rule & Anomaly Matches</div>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Quarantined IPs</span>
            <Ban className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-rose-400 tabular-nums">
              {metrics.blockedIpsCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Active Automated Blocks</div>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Critical Incidents</span>
            <AlertTriangle className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold font-mono text-rose-500 tabular-nums">
              {metrics.criticalEventsCount}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Score $\ge$ 80 / Auto-Mitigated</div>
          </div>
        </div>

        {/* Metric 5 */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Current Threat Level</span>
            <span className="text-[10px] font-mono text-cyan-400">LIVE GAUGE</span>
          </div>
          <div className="mt-2">
            <div className={`text-lg font-bold font-mono truncate ${
              metrics.currentRiskLevel.includes('CRITICAL')
                ? 'text-rose-400'
                : metrics.currentRiskLevel.includes('HIGH')
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}>
              {metrics.currentRiskLevel.split(' ')[0]}
            </div>
            <div className="text-[11px] text-slate-400 font-mono mt-1">{metrics.systemStatus}</div>
          </div>
        </div>
      </div>

      {/* Charts Grid: 4 Visualizations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Attacks Over Time Line Chart */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-5 rounded-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Threat Activity Over Time</h2>
              <p className="text-xs text-slate-400 font-mono">Total requests vs verified attack anomalies</p>
            </div>
          </div>
          <div className="h-60 w-full">
            <Line
              data={attacksTimelineData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'top',
                    labels: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
                  }
                },
                scales: {
                  x: { ticks: { color: '#64748b', font: { family: 'JetBrains Mono' } }, grid: { display: false } },
                  y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30, 41, 59, 0.7)' } }
                }
              }}
            />
          </div>
        </div>

        {/* Chart 2: Attack Type Distribution Doughnut */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-5 rounded-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Attack Type Distribution</h2>
              <p className="text-xs text-slate-400 font-mono">Signatures classified by ZeroAttack engine</p>
            </div>
          </div>
          <div className="h-60 w-full flex items-center justify-center">
            <Doughnut
              data={attackTypeChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'right',
                    labels: { color: '#cbd5e1', font: { family: 'JetBrains Mono', size: 10 }, boxWidth: 12 }
                  }
                }
              }}
            />
          </div>
        </div>

        {/* Chart 3: Severity Breakdown Bar Chart */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-5 rounded-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Incident Severity Distribution</h2>
              <p className="text-xs text-slate-400 font-mono">LOW, MEDIUM, HIGH, and CRITICAL spectrum</p>
            </div>
          </div>
          <div className="h-56 w-full">
            <Bar
              data={severityChartData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                  x: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono' } }, grid: { display: false } },
                  y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(30, 41, 59, 0.7)' } }
                }
              }}
            />
          </div>
        </div>

        {/* Chart 4: Suspicious IP Activity Top Vectors */}
        <div className="bg-slate-900/80 border border-slate-800/90 p-5 rounded-xl flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Top Malicious Source IPs</h2>
              <p className="text-xs text-slate-400 font-mono">Highest incident frequency hosts</p>
            </div>
            <button onClick={onNavigateToIps} className="text-xs text-cyan-400 hover:underline flex items-center gap-1">
              Firewall list <ArrowUpRight className="w-3 h-3" />
            </button>
          </div>
          <div className="space-y-2.5 font-mono text-xs flex-1">
            {sortedIps.length === 0 ? (
              <p className="text-slate-500 py-8 text-center">No host anomalies recorded yet.</p>
            ) : (
              sortedIps.map(([ip, count]) => {
                const isBlocked = blockedIps.some(b => b.ipAddress === ip && b.status === 'ACTIVE');
                return (
                  <div key={ip} className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-white font-bold">{ip}</span>
                      {isBlocked ? (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                          FIREWALLED
                        </span>
                      ) : (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                          MONITORED
                        </span>
                      )}
                    </div>
                    <div className="text-right">
                      <span className="text-amber-400 font-bold">{count} incident{count > 1 ? 's' : ''}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Live Security-Event Table */}
      <div className="bg-slate-900/80 border border-slate-800/90 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800/90 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">Live Security Event Log</h2>
            <p className="text-xs text-slate-400">Real-time incoming packets inspected by rule & anomaly engines</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onNavigateToMonitor}
              className="px-3 py-1.5 text-xs font-semibold text-cyan-300 bg-cyan-950/80 border border-cyan-800 rounded-lg hover:bg-cyan-900 transition"
            >
              + Simulate Request
            </button>
            <button
              onClick={onNavigateToEvents}
              className="text-xs text-slate-400 hover:text-white transition"
            >
              View All ({events.length}) &rarr;
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-mono uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="p-3.5">Time</th>
                <th className="p-3.5">IP Address</th>
                <th className="p-3.5">Attack Type</th>
                <th className="p-3.5 text-right">Risk Score</th>
                <th className="p-3.5">Severity</th>
                <th className="p-3.5">Action</th>
                <th className="p-3.5">Status</th>
                <th className="p-3.5 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 font-mono">
              {events.slice(0, 7).map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => onSelectEvent(ev)}
                  className="hover:bg-slate-800/40 cursor-pointer transition"
                >
                  <td className="p-3.5 text-slate-400 tabular-nums">
                    {ev.timestamp.split(' ')[1] || ev.timestamp}
                  </td>
                  <td className="p-3.5 font-bold text-white">
                    {ev.sourceIp}
                  </td>
                  <td className="p-3.5 text-cyan-300">
                    {ev.attackType}
                  </td>
                  <td className="p-3.5 text-right font-bold text-white tabular-nums">
                    <span className={
                      ev.riskScore >= 80 ? 'text-rose-400' : ev.riskScore >= 60 ? 'text-orange-400' : 'text-slate-300'
                    }>
                      {ev.riskScore}
                    </span>
                    <span className="text-slate-500 font-normal">/100</span>
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
                    <span className="text-cyan-400 hover:text-cyan-300 font-sans text-xs">
                      Inspect &rarr;
                    </span>
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
