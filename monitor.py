"""
monitor.py — Process Monitoring Engine
========================================
Uses psutil to enumerate all running processes, compute resource usage,
and apply the three flagging rules defined in DESIGN.md:

  Rule 1 — High CPU:    cpu_percent > CPU_THRESHOLD
  Rule 2 — High Memory: RSS in MB > MEM_THRESHOLD_MB
  Rule 3 — Unknown:     process name not in WHITELIST

Priority: High CPU > High RAM > Unknown
(First matching rule becomes the reason label.)
"""

import psutil
import config
from whitelist import WHITELIST

# Number of logical CPU cores — used to normalize per-process cpu_percent
# psutil returns per-core percentages (e.g., 100% = 1 full core).
# Dividing by cpu_count() converts to "% of total CPU" matching Task Manager.
_CPU_COUNT = psutil.cpu_count(logical=True) or 1


def get_all_processes():
    """
    Scan every running process and return a list of process dicts.

    Each dict contains:
        pid          (int)   — Process ID
        name         (str)   — Process executable name
        cpu_percent  (float) — CPU usage percentage
        mem_mb       (float) — Resident memory in megabytes
        status       (str)   — Process status (running, sleeping, etc.)
        exe_path     (str)   — Full path to the executable
        flagged      (bool)  — Whether the process triggered any rule
        reason       (str)   — "High CPU" / "High RAM" / "Unknown" / ""

    Processes that cannot be read (zombie, access denied) are silently skipped.
    """
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status', 'exe']):
        try:
            info = proc.info
            pid = info.get("pid", 0)
            name = info.get("name", "") or ""
            # Normalize: psutil gives per-core %, divide by core count to
            # match Windows Task Manager's "% of total CPU" display.
            cpu_raw = info.get("cpu_percent", 0.0) or 0.0
            cpu = round(cpu_raw / _CPU_COUNT, 2)
            mem_info = info.get("memory_info")
            mem_mb = round((mem_info.rss / (1024 * 1024)), 2) if mem_info else 0.0
            status = info.get("status", "") or ""
            exe_path = info.get("exe", "") or ""

            # ── Apply flagging rules (priority order) ──────────────────────
            flagged = False
            reason = ""

            # Rule 1 — High CPU (cpu is already normalized to total-CPU %)
            if cpu > config.CPU_THRESHOLD:
                flagged = True
                reason = "High CPU"

            # Rule 2 — High Memory
            elif mem_mb > config.MEM_THRESHOLD_MB:
                flagged = True
                reason = "High RAM"

            # Rule 3 — Unknown executable name
            elif name.lower() not in WHITELIST:
                flagged = True
                reason = "Unknown"

            processes.append({
                "pid": pid,
                "name": name,
                "cpu_percent": round(cpu, 1),
                "mem_mb": mem_mb,
                "status": status,
                "exe_path": exe_path,
                "flagged": flagged,
                "reason": reason,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process vanished or we lack permission — skip it
            continue

    return processes


def get_system_stats():
    """
    Return system-wide CPU and memory statistics.

    Returns:
        dict with keys:
            cpu_percent  (float) — Overall CPU usage (1-second sample)
            ram_percent  (float) — Percentage of RAM in use
            ram_used_mb  (float) — RAM currently used in MB
            ram_total_mb (float) — Total installed RAM in MB
    """
    mem = psutil.virtual_memory()

    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": mem.percent,
        "ram_used_mb": round(mem.used / (1024 * 1024), 1),
        "ram_total_mb": round(mem.total / (1024 * 1024), 1),
    }
