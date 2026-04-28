/**
 * dashboard.js — Frontend Logic for Suspicious Process Monitor
 * ==============================================================
 * Handles AJAX polling, table rendering, search filtering, column sorting,
 * threshold slider changes (with POST to /api/config), CSV export trigger,
 * system stats gauges, live clock, and flagged log panel updates.
 *
 * No external JS frameworks — pure vanilla JavaScript with fetch().
 */

// ── State ────────────────────────────────────────────────────────────────────
let allProcesses = [];          // Full process list from last API call
let sortColumn = "cpu_percent"; // Current sort column
let sortDirection = "desc";     // "asc" or "desc"
let autoRefresh = true;         // Auto-refresh toggle state
let pollingTimer = null;        // setInterval handle
const POLL_INTERVAL = 5000;     // Matches config.POLL_INTERVAL_MS


// ── Initialization ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initControls();
    initSortableHeaders();
    fetchSystemStats();
    fetchProcesses();
    fetchFlaggedLog();
    startPolling();
});


// ── Live Clock ───────────────────────────────────────────────────────────────
function initClock() {
    const clockEl = document.getElementById("live-clock");
    function tick() {
        const now = new Date();
        clockEl.textContent = now.toLocaleTimeString("en-US", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: true,
        });
    }
    tick();
    setInterval(tick, 1000);
}


// ── Controls Setup ───────────────────────────────────────────────────────────
function initControls() {
    // Search input — filter the process table
    const searchInput = document.getElementById("search-input");
    searchInput.addEventListener("input", () => renderProcessTable());

    // CPU threshold slider
    const cpuSlider = document.getElementById("cpu-slider");
    const cpuValue = document.getElementById("cpu-slider-value");
    cpuSlider.addEventListener("input", () => {
        cpuValue.textContent = cpuSlider.value + "%";
    });
    cpuSlider.addEventListener("change", () => {
        postConfig({ cpu_threshold: parseInt(cpuSlider.value) });
    });

    // RAM threshold slider
    const ramSlider = document.getElementById("ram-slider");
    const ramValue = document.getElementById("ram-slider-value");
    ramSlider.addEventListener("input", () => {
        ramValue.textContent = ramSlider.value + " MB";
    });
    ramSlider.addEventListener("change", () => {
        postConfig({ mem_threshold_mb: parseInt(ramSlider.value) });
    });

    // Export CSV button
    const exportBtn = document.getElementById("export-csv-btn");
    exportBtn.addEventListener("click", () => {
        window.location.href = "/api/export/csv";
    });

    // Auto-refresh toggle
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
        if (th.getAttribute("data-sort") === sortColumn) {
            indicator.textContent = sortDirection === "asc" ? " ▲" : " ▼";
        } else {
            indicator.textContent = "";
        }
    });
}


// ── Polling ──────────────────────────────────────────────────────────────────
function startPolling() {
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(() => {
        fetchSystemStats();
        fetchProcesses();
        fetchFlaggedLog();
    }, POLL_INTERVAL);
}

function stopPolling() {
    if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
    }
}


// ── Fetch System Stats ──────────────────────────────────────────────────────
function fetchSystemStats() {
    fetch("/api/system")
        .then((res) => res.json())
        .then((data) => {
            updateGauge("cpu-gauge", data.cpu_percent);
            updateGauge("ram-gauge", data.ram_percent);
            document.getElementById("cpu-percent-text").textContent =
                data.cpu_percent.toFixed(1) + "%";
            document.getElementById("ram-percent-text").textContent =
                data.ram_percent.toFixed(1) + "%";
            document.getElementById("ram-detail-text").textContent =
                `${data.ram_used_mb} / ${data.ram_total_mb} MB`;
        })
        .catch((err) => console.error("System stats error:", err));
}

function updateGauge(canvasId, percent) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    // Clamp to [0, 100] so the arc never overflows even with stale data
    const clampedPercent = Math.min(100, Math.max(0, percent));
    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(cx, cy) - 10;
    const startAngle = 0.75 * Math.PI;
    const endAngle = 2.25 * Math.PI;
    const sweepAngle = startAngle + (endAngle - startAngle) * (clampedPercent / 100);

    // Determine color based on value
    let color = "#22c55e"; // green
    if (clampedPercent >= 80) color = "#ef4444"; // red
    else if (clampedPercent >= 50) color = "#eab308"; // yellow

    ctx.clearRect(0, 0, w, h);

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = "#334155";
    ctx.lineWidth = 12;
    ctx.lineCap = "round";
    ctx.stroke();

    // Value arc
    if (clampedPercent > 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, sweepAngle);
        ctx.strokeStyle = color;
        ctx.lineWidth = 12;
        ctx.lineCap = "round";
        ctx.stroke();
    }
}


// ── Fetch Processes ─────────────────────────────────────────────────────────
function fetchProcesses() {
    fetch("/api/processes")
        .then((res) => res.json())
        .then((data) => {
            allProcesses = data;

            // Update counts in header
            const total = data.length;
            const flagged = data.filter((p) => p.flagged).length;
            document.getElementById("total-count").textContent = total;
            document.getElementById("flagged-count").textContent = flagged;

            renderProcessTable();
        })
        .catch((err) => console.error("Process fetch error:", err));
}


// ── Render Process Table ────────────────────────────────────────────────────
function renderProcessTable() {
    const searchTerm = document
        .getElementById("search-input")
        .value.toLowerCase()
        .trim();

    // Filter by search term
    let filtered = allProcesses;
    if (searchTerm) {
        filtered = allProcesses.filter(
            (p) =>
                p.name.toLowerCase().includes(searchTerm) ||
                p.exe_path.toLowerCase().includes(searchTerm) ||
                String(p.pid).includes(searchTerm)
        );
    }

    // Sort
    filtered.sort((a, b) => {
        let valA = a[sortColumn];
        let valB = b[sortColumn];

        // Numeric columns
        if (typeof valA === "number" && typeof valB === "number") {
            return sortDirection === "asc" ? valA - valB : valB - valA;
        }

        // Boolean
        if (typeof valA === "boolean") {
            valA = valA ? 1 : 0;
            valB = valB ? 1 : 0;
            return sortDirection === "asc" ? valA - valB : valB - valA;
        }

        // String comparison
        valA = String(valA).toLowerCase();
        valB = String(valB).toLowerCase();
        if (valA < valB) return sortDirection === "asc" ? -1 : 1;
        if (valA > valB) return sortDirection === "asc" ? 1 : -1;
        return 0;
    });

    // Build rows
    const tbody = document.getElementById("process-tbody");
    tbody.innerHTML = "";

    filtered.forEach((proc) => {
        const tr = document.createElement("tr");

        // Row coloring based on flag reason
        if (proc.flagged) {
            if (proc.reason === "High CPU" || proc.reason === "High RAM") {
                tr.className =
                    "border-b border-red-900/40 bg-red-950/30 hover:bg-red-950/50 transition-colors";
            } else if (proc.reason === "Unknown") {
                tr.className =
                    "border-b border-orange-900/40 bg-orange-950/30 hover:bg-orange-950/50 transition-colors";
            }
        } else {
            tr.className =
                "border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors";
        }

        tr.innerHTML = `
            <td class="px-4 py-2.5 text-sm font-mono">${proc.pid}</td>
            <td class="px-4 py-2.5 text-sm font-semibold">${escapeHtml(proc.name)}</td>
            <td class="px-4 py-2.5 text-sm font-mono text-right ${proc.cpu_percent > 70 ? "text-red-400 font-bold" : ""}">${proc.cpu_percent.toFixed(1)}%</td>
            <td class="px-4 py-2.5 text-sm font-mono text-right ${proc.mem_mb > 500 ? "text-red-400 font-bold" : ""}">${proc.mem_mb.toFixed(1)}</td>
            <td class="px-4 py-2.5 text-sm">
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${getStatusClass(proc.status)}">${proc.status}</span>
            </td>
            <td class="px-4 py-2.5 text-xs text-slate-400 max-w-xs truncate" title="${escapeHtml(proc.exe_path)}">${escapeHtml(proc.exe_path || "—")}</td>
            <td class="px-4 py-2.5 text-sm font-semibold">
                ${proc.flagged ? `<span class="${getReasonClass(proc.reason)}">${proc.reason}</span>` : '<span class="text-emerald-400">Clean</span>'}
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Update filtered count
    document.getElementById("showing-count").textContent = filtered.length;
}


// ── Fetch Flagged Log ───────────────────────────────────────────────────────
function fetchFlaggedLog() {
    fetch("/api/flagged")
        .then((res) => res.json())
        .then((data) => {
            const tbody = document.getElementById("flagged-tbody");
            tbody.innerHTML = "";

            data.forEach((entry) => {
                const tr = document.createElement("tr");
                tr.className =
                    "border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors";

                // Format timestamp
                const ts = new Date(entry.timestamp);
                const timeStr = ts.toLocaleString("en-US", {
                    month: "short",
                    day: "2-digit",
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hour12: true,
                });

                tr.innerHTML = `
                    <td class="px-4 py-2 text-xs text-slate-400">${timeStr}</td>
                    <td class="px-4 py-2 text-sm font-mono">${entry.pid}</td>
                    <td class="px-4 py-2 text-sm font-semibold">${escapeHtml(entry.name)}</td>
                    <td class="px-4 py-2 text-sm font-semibold">
                        <span class="${getReasonClass(entry.reason)}">${entry.reason}</span>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        })
        .catch((err) => console.error("Flagged log error:", err));
}


// ── POST Config Updates ─────────────────────────────────────────────────────
function postConfig(configData) {
    fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(configData),
    })
        .then((res) => res.json())
        .then((data) => {
            console.log("Config updated:", data);
            // Immediately re-fetch processes with new thresholds
            fetchProcesses();
        })
        .catch((err) => console.error("Config update error:", err));
}


// ── Helper: Status Badge Class ──────────────────────────────────────────────
function getStatusClass(status) {
    switch (status) {
        case "running":
            return "bg-emerald-900/60 text-emerald-300";
        case "sleeping":
            return "bg-blue-900/60 text-blue-300";
        case "stopped":
            return "bg-yellow-900/60 text-yellow-300";
        case "zombie":
            return "bg-red-900/60 text-red-300";
        default:
            return "bg-slate-700/60 text-slate-300";
    }
}


// ── Helper: Flag Reason Badge Class ─────────────────────────────────────────
function getReasonClass(reason) {
    switch (reason) {
        case "High CPU":
            return "text-red-400 bg-red-900/40 px-2 py-0.5 rounded-full text-xs";
        case "High RAM":
            return "text-red-400 bg-red-900/40 px-2 py-0.5 rounded-full text-xs";
        case "Unknown":
            return "text-orange-400 bg-orange-900/40 px-2 py-0.5 rounded-full text-xs";
        default:
            return "text-slate-400";
    }
}


// ── Helper: Escape HTML ─────────────────────────────────────────────────────
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
