"""
cooldown.py — Alert Cooldown Manager
======================================
Prevents duplicate email alerts by enforcing a per-PID, per-alert-type
cooldown period. If an alert was sent for a specific (PID, alert_type)
combination within the last ALERT_COOLDOWN_SECONDS (default 5 minutes),
subsequent alerts for that same combination are suppressed.

Thread-safe: all access is guarded by a threading.Lock.
"""

import time
import threading
import config


# ─── Internal State ───────────────────────────────────────────────────────────
# Maps "pid_alerttype" → timestamp of last alert sent
_cooldown_cache: dict[str, float] = {}
_lock = threading.Lock()


def _make_key(pid: int, alert_type: str) -> str:
    """Build a unique cache key from PID and alert type."""
    return f"{pid}_{alert_type}"


def is_on_cooldown(pid: int, alert_type: str) -> bool:
    """
    Check if an alert for this (PID, alert_type) is still within the
    cooldown window.

    Args:
        pid:        Process ID
        alert_type: Alert category string (e.g. "High CPU", "Suspicious Path")

    Returns:
        True if we should suppress this alert, False if it's okay to send.
    """
    key = _make_key(pid, alert_type)
    with _lock:
        last_sent = _cooldown_cache.get(key)
        if last_sent is None:
            return False
        elapsed = time.time() - last_sent
        return elapsed < config.ALERT_COOLDOWN_SECONDS


def record_alert(pid: int, alert_type: str) -> None:
    """
    Record that an alert was just sent for this (PID, alert_type).
    Updates the cooldown timestamp so subsequent duplicates are suppressed.

    Args:
        pid:        Process ID
        alert_type: Alert category string
    """
    key = _make_key(pid, alert_type)
    with _lock:
        _cooldown_cache[key] = time.time()


def cleanup_stale() -> None:
    """
    Remove cooldown entries that have expired (older than 2× cooldown period).
    Called periodically by the alert monitor to prevent unbounded memory growth.
    """
    cutoff = time.time() - (config.ALERT_COOLDOWN_SECONDS * 2)
    with _lock:
        stale_keys = [k for k, ts in _cooldown_cache.items() if ts < cutoff]
        for k in stale_keys:
            del _cooldown_cache[k]


def get_cache_size() -> int:
    """Return the current number of entries in the cooldown cache."""
    with _lock:
        return len(_cooldown_cache)


def clear_cache() -> None:
    """Clear all cooldown entries (used for testing or manual reset)."""
    with _lock:
        _cooldown_cache.clear()
