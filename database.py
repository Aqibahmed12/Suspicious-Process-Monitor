"""
database.py — SQLite Database Layer for Suspicious Process Monitor
===================================================================
Manages both the 'flagged_processes' table (dashboard flagging) and the
'email_alerts' table (email alert system). Provides functions to init
schemas, insert records, retrieve entries, and compute statistics.
"""

import sqlite3
import os
from datetime import datetime, timedelta
from config import DB_PATH


def _get_connection():
    """
    Open a connection to the SQLite database.
    Creates the 'logs/' directory if it does not exist.
    Returns a sqlite3.Connection with Row factory for dict-like access.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def init_db():
    """
    Create all required tables if they do not already exist.
    Called once at application startup from app.py.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    # Original flagged_processes table (dashboard flagging)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flagged_processes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT     NOT NULL,
            pid         INTEGER  NOT NULL,
            name        TEXT     NOT NULL,
            cpu_percent REAL     NOT NULL,
            mem_mb      REAL     NOT NULL,
            exe_path    TEXT,
            reason      TEXT     NOT NULL,
            status      TEXT
        )
    """)

    # New email_alerts table (email alert system)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT     NOT NULL,
            pid         INTEGER  NOT NULL,
            name        TEXT     NOT NULL,
            alert_type  TEXT     NOT NULL,
            severity    TEXT     NOT NULL,
            cpu_percent REAL,
            mem_mb      REAL,
            exe_path    TEXT,
            reason      TEXT     NOT NULL,
            email_sent  INTEGER  DEFAULT 0,
            status      TEXT,
            username    TEXT,
            start_time  TEXT,
            recommended_action TEXT
        )
    """)

    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# FLAGGED PROCESSES (Dashboard — original functionality)
# ═══════════════════════════════════════════════════════════════════════════════

def log_flagged_process(process):
    """
    Insert a single flagged process record into the database.

    Args:
        process (dict): Must contain keys —
            pid, name, cpu_percent, mem_mb, exe_path, reason, status
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO flagged_processes
            (timestamp, pid, name, cpu_percent, mem_mb, exe_path, reason, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        process.get("pid", 0),
        process.get("name", ""),
        process.get("cpu_percent", 0.0),
        process.get("mem_mb", 0.0),
        process.get("exe_path", ""),
        process.get("reason", ""),
        process.get("status", ""),
    ))
    conn.commit()
    conn.close()


def get_recent_flagged(limit=20):
    """
    Retrieve the most recent flagged process entries.

    Args:
        limit (int): Maximum number of rows to return (default 20).

    Returns:
        list[dict]: Each dict contains id, timestamp, pid, name,
                    cpu_percent, mem_mb, exe_path, reason, status.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, pid, name, cpu_percent, mem_mb,
               exe_path, reason, status
        FROM flagged_processes
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_all_flagged():
    """
    Retrieve ALL flagged process entries (used for CSV export).

    Returns:
        list[dict]: Complete history of flagged events.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, pid, name, cpu_percent, mem_mb,
               exe_path, reason, status
        FROM flagged_processes
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_logs():
    """
    Delete all rows from the flagged_processes table.
    Used when the user wants to reset the flagged event history.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM flagged_processes")
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL ALERTS (New — Email Alert System)
# ═══════════════════════════════════════════════════════════════════════════════

def log_email_alert(alert: dict, email_sent: bool = False):
    """
    Insert an email alert record into the database.

    Args:
        alert (dict): AlertEvent from alert_engine with keys:
            timestamp, pid, name, alert_type, severity, cpu_percent,
            mem_mb, exe_path, reason, status, user, start_time,
            recommended_action
        email_sent (bool): Whether the email was successfully sent.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO email_alerts
            (timestamp, pid, name, alert_type, severity, cpu_percent,
             mem_mb, exe_path, reason, email_sent, status, username,
             start_time, recommended_action)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("timestamp", datetime.now().isoformat()),
        alert.get("pid", 0),
        alert.get("name", ""),
        alert.get("alert_type", ""),
        alert.get("severity", "INFO"),
        alert.get("cpu_percent", 0.0),
        alert.get("mem_mb", 0.0),
        alert.get("exe_path", ""),
        alert.get("reason", ""),
        1 if email_sent else 0,
        alert.get("status", ""),
        alert.get("user", ""),
        alert.get("start_time", ""),
        alert.get("recommended_action", ""),
    ))
    conn.commit()
    conn.close()


def get_recent_alerts(limit=50) -> list[dict]:
    """
    Retrieve the most recent email alert entries.

    Args:
        limit (int): Maximum number of rows to return.

    Returns:
        list[dict]: Alert records ordered newest first.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, pid, name, alert_type, severity,
               cpu_percent, mem_mb, exe_path, reason, email_sent,
               status, username, start_time, recommended_action
        FROM email_alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alerts_since(since_iso: str) -> list[dict]:
    """
    Retrieve all email alerts since a given ISO timestamp.
    Used for building the daily digest.

    Args:
        since_iso (str): ISO 8601 datetime string.

    Returns:
        list[dict]: All alerts after the given timestamp.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, pid, name, alert_type, severity,
               cpu_percent, mem_mb, exe_path, reason, email_sent,
               status, username, start_time, recommended_action
        FROM email_alerts
        WHERE timestamp >= ?
        ORDER BY id DESC
    """, (since_iso,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_stats() -> dict:
    """
    Compute aggregate statistics for the email alerts table.

    Returns:
        dict with keys:
            total (int), critical (int), warning (int), info (int),
            emails_sent (int), last_24h (int)
    """
    conn = _get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM email_alerts")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_alerts WHERE severity='CRITICAL'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_alerts WHERE severity='WARNING'")
    warning = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_alerts WHERE severity='INFO'")
    info = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM email_alerts WHERE email_sent=1")
    emails_sent = cursor.fetchone()[0]

    # Last 24 hours
    since = (datetime.now() - timedelta(hours=24)).isoformat()
    cursor.execute("SELECT COUNT(*) FROM email_alerts WHERE timestamp >= ?", (since,))
    last_24h = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "critical": critical,
        "warning": warning,
        "info": info,
        "emails_sent": emails_sent,
        "last_24h": last_24h,
    }
