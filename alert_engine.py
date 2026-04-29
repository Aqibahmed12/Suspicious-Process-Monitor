"""
alert_engine.py — Advanced Detection Engine
=============================================
Implements 7 detection rules that analyze running processes and produce
AlertEvent dicts with severity classifications.

Detection Rules:
  1. Sustained High CPU   — CRITICAL
  2. High Memory          — CRITICAL
  3. Unknown Executable   — WARNING
  4. Suspicious Path      — CRITICAL
  5. Suspicious Name      — WARNING
  6. Process Burst        — WARNING
  7. Process Disappearance — INFO

Thread-safe: all shared state guarded by a threading.Lock.
"""

import re
import time
import threading
from collections import deque
from datetime import datetime

import psutil

import config
from whitelist import WHITELIST

# ─── Severity Levels ─────────────────────────────────────────────────────────
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_CRITICAL = "CRITICAL"

# ─── Thread Lock & State ─────────────────────────────────────────────────────
_lock = threading.Lock()
_cpu_history: dict[int, deque] = {}
_new_pid_window: deque = deque()
_known_pids: set[int] = set()
_known_pid_details: dict[int, dict] = {}
_first_scan = True

# Pre-compile suspicious name patterns
_suspicious_name_regexes = [
    re.compile(p, re.IGNORECASE) for p in config.SUSPICIOUS_NAME_PATTERNS
]


def _build_alert(**kw) -> dict:
    """Construct a standardized AlertEvent dictionary."""
    return {
        "timestamp": kw.get("timestamp", ""),
        "pid": kw.get("pid", 0),
        "name": kw.get("name", ""),
        "alert_type": kw.get("alert_type", ""),
        "severity": kw.get("severity", SEVERITY_INFO),
        "cpu_percent": kw.get("cpu_percent", 0.0),
        "mem_mb": kw.get("mem_mb", 0.0),
        "exe_path": kw.get("exe_path", ""),
        "reason": kw.get("reason", ""),
        "status": kw.get("status", ""),
        "user": kw.get("username", ""),
        "start_time": kw.get("start_time", ""),
        "recommended_action": kw.get("recommended_action", ""),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# RULE IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _check_sustained_cpu(pid, name, cpu, mem_mb, exe_path,
                          status, username, start_time, now, now_iso):
    """Rule 1: CPU > threshold continuously for sustain window."""
    with _lock:
        if pid not in _cpu_history:
            _cpu_history[pid] = deque(maxlen=60)
        _cpu_history[pid].append((now, cpu))
        cutoff = now - config.ALERT_CPU_SUSTAIN_SECONDS - 10
        while _cpu_history[pid] and _cpu_history[pid][0][0] < cutoff:
            _cpu_history[pid].popleft()
        samples = [(ts, c) for ts, c in _cpu_history[pid]
                   if ts >= now - config.ALERT_CPU_SUSTAIN_SECONDS]
        if len(samples) >= 3 and all(c > config.ALERT_CPU_THRESHOLD for _, c in samples):
            avg = round(sum(c for _, c in samples) / len(samples), 1)
            return _build_alert(
                timestamp=now_iso, pid=pid, name=name,
                alert_type="Sustained High CPU", severity=SEVERITY_CRITICAL,
                cpu_percent=avg, mem_mb=mem_mb, exe_path=exe_path,
                status=status, username=username, start_time=start_time,
                reason=f"CPU averaged {avg}% for {config.ALERT_CPU_SUSTAIN_SECONDS}s",
                recommended_action="Investigate for cryptominers or runaway tasks. Consider terminating.",
            )
    return None


def _check_high_memory(pid, name, cpu, mem_mb, mem_pct,
                        exe_path, status, username, start_time, now_iso):
    """Rule 2: Memory > threshold MB or > threshold % of system RAM."""
    reasons = []
    if mem_mb > config.ALERT_MEM_THRESHOLD_MB:
        reasons.append(f"Using {mem_mb} MB (limit: {config.ALERT_MEM_THRESHOLD_MB} MB)")
    if mem_pct > config.ALERT_MEM_PERCENT_THRESHOLD:
        reasons.append(f"Using {mem_pct}% of system RAM (limit: {config.ALERT_MEM_PERCENT_THRESHOLD}%)")
    if reasons:
        return _build_alert(
            timestamp=now_iso, pid=pid, name=name,
            alert_type="High Memory", severity=SEVERITY_CRITICAL,
            cpu_percent=cpu, mem_mb=mem_mb, exe_path=exe_path,
            status=status, username=username, start_time=start_time,
            reason=" | ".join(reasons),
            recommended_action="Check for memory leaks. Restart the process if usage is abnormal.",
        )
    return None


def _check_unknown_executable(pid, name, cpu, mem_mb, exe_path,
                               status, username, start_time, now_iso):
    """Rule 3: Process name not in WHITELIST."""
    if name.lower() not in WHITELIST:
        return _build_alert(
            timestamp=now_iso, pid=pid, name=name,
            alert_type="Unknown Executable", severity=SEVERITY_WARNING,
            cpu_percent=cpu, mem_mb=mem_mb, exe_path=exe_path,
            status=status, username=username, start_time=start_time,
            reason=f"'{name}' is not in the trusted whitelist",
            recommended_action="Verify legitimacy. Scan with antivirus if unknown.",
        )
    return None


def _check_suspicious_path(pid, name, cpu, mem_mb, exe_path,
                            status, username, start_time, now_iso):
    """Rule 4: Executable running from temp/appdata/tmp directories."""
    if not exe_path:
        return None
    path_lower = exe_path.lower()
    for pattern in config.SUSPICIOUS_PATHS:
        if pattern.lower() in path_lower:
            return _build_alert(
                timestamp=now_iso, pid=pid, name=name,
                alert_type="Suspicious Path", severity=SEVERITY_CRITICAL,
                cpu_percent=cpu, mem_mb=mem_mb, exe_path=exe_path,
                status=status, username=username, start_time=start_time,
                reason=f"Running from suspicious directory: '{pattern}'",
                recommended_action="Executables in temp directories are often malware. Quarantine and scan.",
            )
    return None


def _check_suspicious_name(pid, name, cpu, mem_mb, exe_path,
                            status, username, start_time, now_iso):
    """Rule 5: Process name matches malicious naming patterns.
    Skips processes that are in the WHITELIST to avoid false positives."""
    # Skip whitelisted processes — they are known-good
    if name.lower() in WHITELIST:
        return None
    for regex in _suspicious_name_regexes:
        if regex.match(name):
            return _build_alert(
                timestamp=now_iso, pid=pid, name=name,
                alert_type="Suspicious Name", severity=SEVERITY_WARNING,
                cpu_percent=cpu, mem_mb=mem_mb, exe_path=exe_path,
                status=status, username=username, start_time=start_time,
                reason=f"Name matches suspicious pattern '{regex.pattern}'",
                recommended_action="Verify digital signature. Scan with antivirus.",
            )
    return None


def _check_process_burst(current_pids, now, now_iso):
    """Rule 6: Too many new processes spawned in the burst window."""
    alerts = []
    with _lock:
        new_pids = current_pids - _known_pids
        for pid in new_pids:
            _new_pid_window.append((now, pid))
        cutoff = now - config.BURST_WINDOW_SECONDS
        while _new_pid_window and _new_pid_window[0][0] < cutoff:
            _new_pid_window.popleft()
        if len(_new_pid_window) > config.BURST_THRESHOLD:
            alerts.append(_build_alert(
                timestamp=now_iso, pid=0, name="SYSTEM",
                alert_type="Process Burst", severity=SEVERITY_WARNING,
                reason=f"{len(_new_pid_window)} new processes in {config.BURST_WINDOW_SECONDS}s (limit: {config.BURST_THRESHOLD})",
                recommended_action="Investigate for fork bombs or malware spawning.",
            ))
            _new_pid_window.clear()
    return alerts


def _check_process_disappearance(current_pids, now_iso):
    """Rule 7: Previously-known non-whitelisted PID vanished."""
    alerts = []
    with _lock:
        disappeared = _known_pids - current_pids
        for pid in disappeared:
            if pid <= 4:
                continue
            details = _known_pid_details.get(pid, {})
            name = details.get("name", "Unknown")
            if name.lower() in WHITELIST:
                continue
            alerts.append(_build_alert(
                timestamp=now_iso, pid=pid, name=name,
                alert_type="Process Disappeared", severity=SEVERITY_INFO,
                cpu_percent=details.get("cpu_percent", 0.0),
                mem_mb=details.get("mem_mb", 0.0),
                exe_path=details.get("exe_path", ""),
                status="terminated", username=details.get("username", ""),
                start_time=details.get("start_time", ""),
                reason=f"'{name}' (PID {pid}) vanished between scans",
                recommended_action="If suspicious, check system logs for related events.",
            ))
    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def run_detection_scan() -> list[dict]:
    """Execute all 7 detection rules against current processes."""
    global _first_scan

    alerts = []
    now = time.time()
    now_iso = datetime.now().isoformat()
    current_pids = set()
    current_pid_details = {}

    sys_mem = psutil.virtual_memory()
    total_ram_mb = sys_mem.total / (1024 * 1024)
    cpu_count = psutil.cpu_count(logical=True) or 1

    for proc in psutil.process_iter([
        'pid', 'name', 'cpu_percent', 'memory_info',
        'status', 'exe', 'username', 'create_time'
    ]):
        try:
            info = proc.info
            pid = info.get("pid", 0)
            name = info.get("name", "") or ""
            cpu_raw = info.get("cpu_percent", 0.0) or 0.0
            cpu = round(cpu_raw / cpu_count, 2)
            mem_info = info.get("memory_info")
            mem_mb = round((mem_info.rss / (1024 * 1024)), 2) if mem_info else 0.0
            mem_pct = round((mem_mb / total_ram_mb) * 100, 1) if total_ram_mb > 0 else 0.0
            status = info.get("status", "") or ""
            exe_path = info.get("exe", "") or ""
            username = info.get("username", "") or ""
            ct = info.get("create_time")
            start_time = ""
            if ct:
                try:
                    start_time = datetime.fromtimestamp(ct).isoformat()
                except (OSError, ValueError):
                    pass

            current_pids.add(pid)
            current_pid_details[pid] = {
                "name": name, "cpu_percent": cpu, "mem_mb": mem_mb,
                "exe_path": exe_path, "status": status,
                "username": username, "start_time": start_time,
            }

            # Run per-process rules
            for check_fn, args in [
                (_check_sustained_cpu, (pid, name, cpu, mem_mb, exe_path,
                                        status, username, start_time, now, now_iso)),
                (_check_high_memory, (pid, name, cpu, mem_mb, mem_pct,
                                      exe_path, status, username, start_time, now_iso)),
                (_check_unknown_executable, (pid, name, cpu, mem_mb, exe_path,
                                             status, username, start_time, now_iso)),
                (_check_suspicious_path, (pid, name, cpu, mem_mb, exe_path,
                                          status, username, start_time, now_iso)),
                (_check_suspicious_name, (pid, name, cpu, mem_mb, exe_path,
                                          status, username, start_time, now_iso)),
            ]:
                result = check_fn(*args)
                if result:
                    alerts.append(result)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # System-level rules
    if not _first_scan:
        alerts.extend(_check_process_burst(current_pids, now, now_iso))
        alerts.extend(_check_process_disappearance(current_pids, now_iso))

    # Update state for next scan
    with _lock:
        _known_pids.clear()
        _known_pids.update(current_pids)
        _known_pid_details.clear()
        _known_pid_details.update(current_pid_details)
        _first_scan = False

    return alerts
