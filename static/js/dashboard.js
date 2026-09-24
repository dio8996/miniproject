// ZeroAttack Dashboard JavaScript
document.addEventListener("DOMContentLoaded", () => {
  fetchDashboardData();
  // Poll every 10 seconds for real-time threat feed
  setInterval(fetchDashboardData, 10000);
});

let attackChartInstance = null;
let severityChartInstance = null;

async function fetchDashboardData() {
  try {
    const res = await fetch("/api/dashboard/stats");
    if (!res.ok) return;
    const data = await res.json();
    
    // Update stats
    if (data.metrics) {
      document.getElementById("stat-total-requests").innerText = data.metrics.total_requests.toLocaleString();
      document.getElementById("stat-detected-attacks").innerText = data.metrics.detected_attacks.toLocaleString();
      document.getElementById("stat-blocked-ips").innerText = data.metrics.blocked_ips_count.toLocaleString();
      
      const riskEl = document.getElementById("stat-risk-level");
      riskEl.innerText = data.metrics.current_risk_level;
      riskEl.style.color = data.metrics.risk_color;
    }

    // Render Charts
    renderAttackTypeChart(data.charts.attack_type_distribution);
    renderSeverityChart(data.charts.severity_distribution);

    // Render Event table
    renderRecentEvents(data.recent_events || []);
  } catch (err) {
    console.error("Dashboard poll failed", err);
  }
}

function renderAttackTypeChart(chartData) {
  const ctx = document.getElementById("attackTypeChart");
  if (!ctx) return;
  if (attackChartInstance) attackChartInstance.destroy();

  attackChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: chartData.labels,
      datasets: [{
        data: chartData.data,
        backgroundColor: [
          "#ef4444", // SQLi Red
          "#f97316", // XSS Orange
          "#a855f7", // Brute Force Purple
          "#06b6d4", // Tampering Cyan
          "#eab308"  // Anomaly Yellow
        ],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } } }
      }
    }
  });
}

function renderSeverityChart(chartData) {
  const ctx = document.getElementById("severityChart");
  if (!ctx) return;
  if (severityChartInstance) severityChartInstance.destroy();

  severityChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: chartData.labels,
      datasets: [{
        label: "Incidents",
        data: chartData.data,
        backgroundColor: [
          "#10b981", // LOW Green
          "#eab308", // MEDIUM Yellow
          "#f97316", // HIGH Orange
          "#ef4444"  // CRITICAL Red
        ],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8", font: { family: "JetBrains Mono" } }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function renderRecentEvents(events) {
  const tbody = document.getElementById("live-events-tbody");
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-500">No security incidents logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => {
    let sevBadge = "badge-low";
    if (e.severity === "CRITICAL") sevBadge = "badge-critical";
    else if (e.severity === "HIGH") sevBadge = "badge-high";
    else if (e.severity === "MEDIUM") sevBadge = "badge-medium";

    return `
      <tr class="hover:bg-slate-900/40 cursor-pointer" onclick="window.location='/events/${e.id}'">
        <td class="p-3 text-slate-400">${e.timestamp.split(" ")[1] || e.timestamp}</td>
        <td class="p-3 text-white font-semibold">${e.source_ip}</td>
        <td class="p-3 text-cyan-300">${e.attack_type}</td>
        <td class="p-3 font-bold">${e.risk_score}/100</td>
        <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] ${sevBadge}">${e.severity}</span></td>
        <td class="p-3 text-rose-300 font-semibold">${e.action_taken}</td>
        <td class="p-3 text-slate-400">${e.status}</td>
      </tr>
    `;
  }).join("");
}
