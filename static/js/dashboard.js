/**
 * dashboard.js — Frontend Logic for Suspicious Process Monitor
 * ==============================================================
 * Handles AJAX polling, table rendering, search filtering, column sorting,
 * threshold sliders, CSV export, system gauges, live clock, flagged log,
 * email alerts panel, and email configuration UI.
 */

// ── State ────────────────────────────────────────────────────────────────────
let allProcesses = [];
let sortColumn = "cpu_percent";
let sortDirection = "desc";
let autoRefresh = true;
let pollingTimer = null;
const POLL_INTERVAL = 5000;

// ── Initialization ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initControls();
    initSortableHeaders();
    initEmailConfig();
    fetchSystemStats();
    fetchProcesses();
    fetchFlaggedLog();
    fetchAlerts();
    fetchAlertStats();
    startPolling();
});

// ── Live Clock ───────────────────────────────────────────────────────────────
function initClock() {
    const clockEl = document.getElementById("live-clock");
    function tick() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString("en-US", {
            hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true,
        });
    }
    tick();
    setInterval(tick, 1000);
}

// ── Controls Setup ───────────────────────────────────────────────────────────
function initControls() {
    document.getElementById("search-input").addEventListener("input", () => renderProcessTable());

    const cpuSlider = document.getElementById("cpu-slider");
    const cpuValue = document.getElementById("cpu-slider-value");
    cpuSlider.addEventListener("input", () => { cpuValue.textContent = cpuSlider.value + "%"; });
    cpuSlider.addEventListener("change", () => { postConfig({ cpu_threshold: parseInt(cpuSlider.value) }); });

    const ramSlider = document.getElementById("ram-slider");
    const ramValue = document.getElementById("ram-slider-value");
    ramSlider.addEventListener("input", () => { ramValue.textContent = ramSlider.value + " MB"; });
    ramSlider.addEventListener("change", () => { postConfig({ mem_threshold_mb: parseInt(ramSlider.value) }); });

    document.getElementById("export-csv-btn").addEventListener("click", () => {
        window.location.href = "/api/export/csv";
    });

    const toggleBtn = document.getElementById("auto-refresh-toggle");
    toggleBtn.addEventListener("click", () => {
        autoRefresh = !autoRefresh;
        if (autoRefresh) {
            toggleBtn.textContent = "Auto-Refresh: ON";
            toggleBtn.classList.remove("bg-red-600");
            toggleBtn.classList.add("bg-emerald-600");
            startPolling();
        } else {
            toggleBtn.textContent = "Auto-Refresh: OFF";
            toggleBtn.classList.remove("bg-emerald-600");
            toggleBtn.classList.add("bg-red-600");
            stopPolling();
        }
    });
}

// ── Sortable Table Headers ───────────────────────────────────────────────────
function initSortableHeaders() {
    document.querySelectorAll("th[data-sort]").forEach((th) => {
        th.addEventListener("click", () => {
            const col = th.getAttribute("data-sort");
            if (sortColumn === col) {
                sortDirection = sortDirection === "asc" ? "desc" : "asc";
            } else {
                sortColumn = col;
                sortDirection = "desc";
            }
            updateSortIndicators();
            renderProcessTable();
        });
    });
    updateSortIndicators();
}

function updateSortIndicators() {
    document.querySelectorAll("th[data-sort]").forEach((th) => {
        const indicator = th.querySelector(".sort-indicator");
        if (!indicator) return;
        indicator.textContent = th.getAttribute("data-sort") === sortColumn
            ? (sortDirection === "asc" ? " ▲" : " ▼") : "";
    });
}

// ── Polling ──────────────────────────────────────────────────────────────────
function startPolling() {
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(() => {
        fetchSystemStats();
        fetchProcesses();
        fetchFlaggedLog();
        fetchAlerts();
        fetchAlertStats();
    }, POLL_INTERVAL);
}

function stopPolling() {
    if (pollingTimer) { clearInterval(pollingTimer); pollingTimer = null; }
}

// ── Fetch System Stats ──────────────────────────────────────────────────────
function fetchSystemStats() {
    fetch("/api/system").then(r => r.json()).then(data => {
        updateGauge("cpu-gauge", data.cpu_percent);
        updateGauge("ram-gauge", data.ram_percent);
        document.getElementById("cpu-percent-text").textContent = data.cpu_percent.toFixed(1) + "%";
        document.getElementById("ram-percent-text").textContent = data.ram_percent.toFixed(1) + "%";
        document.getElementById("ram-detail-text").textContent = `${data.ram_used_mb} / ${data.ram_total_mb} MB`;
    }).catch(e => console.error("System stats error:", e));
}

function updateGauge(canvasId, percent) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const cp = Math.min(100, Math.max(0, percent));
    const w = canvas.width, h = canvas.height;
    const cx = w / 2, cy = h / 2;
    const radius = Math.min(cx, cy) - 10;
    const startAngle = 0.75 * Math.PI, endAngle = 2.25 * Math.PI;
    const sweepAngle = startAngle + (endAngle - startAngle) * (cp / 100);
    let color = "#22c55e";
    if (cp >= 80) color = "#ef4444";
    else if (cp >= 50) color = "#eab308";
    ctx.clearRect(0, 0, w, h);
    ctx.beginPath(); ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = "#334155"; ctx.lineWidth = 12; ctx.lineCap = "round"; ctx.stroke();
    if (cp > 0) {
        ctx.beginPath(); ctx.arc(cx, cy, radius, startAngle, sweepAngle);
        ctx.strokeStyle = color; ctx.lineWidth = 12; ctx.lineCap = "round"; ctx.stroke();
    }
}

// ── Fetch Processes ─────────────────────────────────────────────────────────
function fetchProcesses() {
    fetch("/api/processes").then(r => r.json()).then(data => {
        allProcesses = data;
        document.getElementById("total-count").textContent = data.length;
        document.getElementById("flagged-count").textContent = data.filter(p => p.flagged).length;
        renderProcessTable();
    }).catch(e => console.error("Process fetch error:", e));
}

// ── Render Process Table ────────────────────────────────────────────────────
function renderProcessTable() {
    const searchTerm = document.getElementById("search-input").value.toLowerCase().trim();
    let filtered = allProcesses;
    if (searchTerm) {
        filtered = allProcesses.filter(p =>
            p.name.toLowerCase().includes(searchTerm) ||
            p.exe_path.toLowerCase().includes(searchTerm) ||
            String(p.pid).includes(searchTerm)
        );
    }
    filtered.sort((a, b) => {
        let vA = a[sortColumn], vB = b[sortColumn];
        if (typeof vA === "number" && typeof vB === "number") return sortDirection === "asc" ? vA - vB : vB - vA;
        if (typeof vA === "boolean") { vA = vA ? 1 : 0; vB = vB ? 1 : 0; return sortDirection === "asc" ? vA - vB : vB - vA; }
        vA = String(vA).toLowerCase(); vB = String(vB).toLowerCase();
        if (vA < vB) return sortDirection === "asc" ? -1 : 1;
        if (vA > vB) return sortDirection === "asc" ? 1 : -1;
        return 0;
    });

    const tbody = document.getElementById("process-tbody");
    tbody.innerHTML = "";
    filtered.forEach(proc => {
        const tr = document.createElement("tr");
        if (proc.flagged) {
            tr.className = proc.reason === "Unknown"
                ? "border-b border-orange-900/40 bg-orange-950/30 hover:bg-orange-950/50 transition-colors"
                : "border-b border-red-900/40 bg-red-950/30 hover:bg-red-950/50 transition-colors";
        } else {
            tr.className = "border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors";
        }
        tr.innerHTML = `
            <td class="px-4 py-2.5 text-sm font-mono">${proc.pid}</td>
            <td class="px-4 py-2.5 text-sm font-semibold">${esc(proc.name)}</td>
            <td class="px-4 py-2.5 text-sm font-mono text-right ${proc.cpu_percent > 70 ? 'text-red-400 font-bold' : ''}">${proc.cpu_percent.toFixed(1)}%</td>
            <td class="px-4 py-2.5 text-sm font-mono text-right ${proc.mem_mb > 500 ? 'text-red-400 font-bold' : ''}">${proc.mem_mb.toFixed(1)}</td>
            <td class="px-4 py-2.5 text-sm"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls(proc.status)}">${proc.status}</span></td>
            <td class="px-4 py-2.5 text-xs text-slate-400 max-w-xs truncate" title="${esc(proc.exe_path)}">${esc(proc.exe_path || "—")}</td>
            <td class="px-4 py-2.5 text-sm font-semibold">${proc.flagged ? `<span class="${reasonCls(proc.reason)}">${proc.reason}</span>` : '<span class="text-emerald-400">Clean</span>'}</td>
        `;
        tbody.appendChild(tr);
    });
    document.getElementById("showing-count").textContent = filtered.length;
}

// ── Fetch Flagged Log ───────────────────────────────────────────────────────
function fetchFlaggedLog() {
    fetch("/api/flagged").then(r => r.json()).then(data => {
        const tbody = document.getElementById("flagged-tbody");
        tbody.innerHTML = "";
        data.forEach(entry => {
            const tr = document.createElement("tr");
            tr.className = "border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors";
            const ts = new Date(entry.timestamp);
            const timeStr = ts.toLocaleString("en-US", { month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit", hour12:true });
            tr.innerHTML = `
                <td class="px-4 py-2 text-xs text-slate-400">${timeStr}</td>
                <td class="px-4 py-2 text-sm font-mono">${entry.pid}</td>
                <td class="px-4 py-2 text-sm font-semibold">${esc(entry.name)}</td>
                <td class="px-4 py-2 text-sm font-semibold"><span class="${reasonCls(entry.reason)}">${entry.reason}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }).catch(e => console.error("Flagged log error:", e));
}

// ══════════════════════════════════════════════════════════════════════════════
// EMAIL ALERT SYSTEM UI
// ══════════════════════════════════════════════════════════════════════════════

function fetchAlerts() {
    fetch("/api/alerts").then(r => r.json()).then(data => {
        const tbody = document.getElementById("alerts-tbody");
        tbody.innerHTML = "";
        data.forEach(a => {
            const tr = document.createElement("tr");
            const sevColor = { CRITICAL: "text-red-400", WARNING: "text-orange-400", INFO: "text-cyan-400" }[a.severity] || "text-slate-400";
            const sevBg = { CRITICAL: "bg-red-900/40", WARNING: "bg-orange-900/40", INFO: "bg-cyan-900/40" }[a.severity] || "bg-slate-700";
            tr.className = "border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors";
            const ts = new Date(a.timestamp);
            const timeStr = ts.toLocaleString("en-US", { month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit", second:"2-digit", hour12:true });
            tr.innerHTML = `
                <td class="px-4 py-2 text-xs text-slate-400">${timeStr}</td>
                <td class="px-4 py-2 text-sm font-mono">${a.pid}</td>
                <td class="px-4 py-2 text-sm font-semibold">${esc(a.name)}</td>
                <td class="px-4 py-2 text-sm">${esc(a.alert_type)}</td>
                <td class="px-4 py-2 text-xs font-bold"><span class="px-2 py-0.5 rounded-full ${sevColor} ${sevBg}">${a.severity}</span></td>
                <td class="px-4 py-2 text-sm">${a.email_sent ? '<span class="text-emerald-400">✓</span>' : '<span class="text-slate-500">✗</span>'}</td>
            `;
            tbody.appendChild(tr);
        });
    }).catch(e => console.error("Alerts fetch error:", e));
}

function fetchAlertStats() {
    fetch("/api/alerts/stats").then(r => r.json()).then(data => {
        document.getElementById("stat-critical").textContent = data.critical || 0;
        document.getElementById("stat-warning").textContent = data.warning || 0;
        document.getElementById("stat-info").textContent = data.info || 0;
        document.getElementById("stat-24h").textContent = data.last_24h || 0;
        document.getElementById("alerts-sent-count").textContent = data.emails_sent || 0;
        const badge = document.getElementById("email-status-badge");
        if (data.email_enabled) {
            badge.textContent = data.monitor_running ? "Active" : "Enabled";
            badge.className = "ml-2 px-2 py-0.5 text-[10px] uppercase font-bold rounded-full bg-emerald-900/50 text-emerald-400";
        } else {
            badge.textContent = "Disabled";
            badge.className = "ml-2 px-2 py-0.5 text-[10px] uppercase font-bold rounded-full bg-slate-700 text-slate-400";
        }
    }).catch(e => console.error("Alert stats error:", e));
}

// ── Email Config Toggle ─────────────────────────────────────────────────────
function toggleEmailConfig() {
    const body = document.getElementById("email-config-body");
    const chevron = document.getElementById("config-chevron");
    body.classList.toggle("hidden");
    chevron.style.transform = body.classList.contains("hidden") ? "" : "rotate(180deg)";
}

// ── Email Config Init ───────────────────────────────────────────────────────
function initEmailConfig() {
    document.getElementById("save-email-config-btn").addEventListener("click", saveEmailConfig);
    document.getElementById("test-email-btn").addEventListener("click", sendTestEmail);
}

function saveEmailConfig() {
    const statusEl = document.getElementById("email-config-status");
    statusEl.textContent = "Saving...";
    statusEl.className = "text-sm text-cyan-400 ml-2";

    const payload = {
        smtp_server: document.getElementById("cfg-smtp-server").value,
        smtp_port: parseInt(document.getElementById("cfg-smtp-port").value) || 587,
        smtp_use_tls: document.getElementById("cfg-smtp-tls").checked,
        email_recipients: document.getElementById("cfg-email-recipients").value,
        email_alerts_enabled: document.getElementById("cfg-email-enabled").checked,
        alert_cpu_threshold: parseFloat(document.getElementById("cfg-alert-cpu").value) || 80,
        alert_cpu_sustain_seconds: parseInt(document.getElementById("cfg-alert-cpu-sustain").value) || 30,
        alert_mem_threshold_mb: parseFloat(document.getElementById("cfg-alert-mem").value) || 500,
        alert_mem_percent_threshold: parseFloat(document.getElementById("cfg-alert-mem-pct").value) || 60,
    };

    fetch("/api/alerts/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    }).then(r => r.json()).then(data => {
        statusEl.textContent = "✓ Configuration saved";
        statusEl.className = "text-sm text-emerald-400 ml-2";
        fetchAlertStats();
        setTimeout(() => { statusEl.textContent = ""; }, 3000);
    }).catch(e => {
        statusEl.textContent = "✗ Save failed";
        statusEl.className = "text-sm text-red-400 ml-2";
    });
}

function sendTestEmail() {
    const statusEl = document.getElementById("email-config-status");
    statusEl.textContent = "Sending test email...";
    statusEl.className = "text-sm text-amber-400 ml-2";

    // Save config first, then test
    saveEmailConfigSilent().then(() => {
        return fetch("/api/alerts/test", { method: "POST" });
    }).then(r => r.json()).then(data => {
        if (data.status === "ok") {
            statusEl.textContent = "✓ " + data.message;
            statusEl.className = "text-sm text-emerald-400 ml-2";
        } else {
            statusEl.textContent = "✗ " + data.message;
            statusEl.className = "text-sm text-red-400 ml-2";
        }
        setTimeout(() => { statusEl.textContent = ""; }, 5000);
    }).catch(e => {
        statusEl.textContent = "✗ Test failed: " + e.message;
        statusEl.className = "text-sm text-red-400 ml-2";
    });
}

function saveEmailConfigSilent() {
    const payload = {
        smtp_server: document.getElementById("cfg-smtp-server").value,
        smtp_port: parseInt(document.getElementById("cfg-smtp-port").value) || 587,
        smtp_use_tls: document.getElementById("cfg-smtp-tls").checked,
        email_recipients: document.getElementById("cfg-email-recipients").value,
        email_alerts_enabled: document.getElementById("cfg-email-enabled").checked,
    };
    return fetch("/api/alerts/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
}

// ── POST Dashboard Config ───────────────────────────────────────────────────
function postConfig(configData) {
    fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(configData),
    }).then(r => r.json()).then(() => fetchProcesses())
      .catch(e => console.error("Config update error:", e));
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function statusCls(s) {
    const m = { running:"bg-emerald-900/60 text-emerald-300", sleeping:"bg-blue-900/60 text-blue-300",
                stopped:"bg-yellow-900/60 text-yellow-300", zombie:"bg-red-900/60 text-red-300" };
    return m[s] || "bg-slate-700/60 text-slate-300";
}

function reasonCls(r) {
    if (r === "High CPU" || r === "High RAM") return "text-red-400 bg-red-900/40 px-2 py-0.5 rounded-full text-xs";
    if (r === "Unknown") return "text-orange-400 bg-orange-900/40 px-2 py-0.5 rounded-full text-xs";
    if (r === "Suspicious Path" || r === "Suspicious Name") return "text-purple-400 bg-purple-900/40 px-2 py-0.5 rounded-full text-xs";
    return "text-slate-400";
}

function esc(text) {
    const d = document.createElement("div");
    d.textContent = text;
    return d.innerHTML;
}
