"""
database.py — SQLite Database Layer for Suspicious Process Monitor
===================================================================
Manages the 'flagged_processes' table that stores every flagged event
detected by the monitor engine. Provides functions to initialize the
schema, insert flagged records, retrieve recent entries, and clear logs.
"""

import sqlite3
import os
from datetime import datetime
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


def init_db():
    """
    Create the flagged_processes table if it does not already exist.
    Called once at application startup from app.py.

    Schema (from DESIGN.md):
        id          — INTEGER PRIMARY KEY AUTOINCREMENT
        timestamp   — TEXT (ISO 8601 datetime string)
        pid         — INTEGER
        name        — TEXT
        cpu_percent — REAL
        mem_mb      — REAL
        exe_path    — TEXT
        reason      — TEXT ("High CPU" / "High RAM" / "Unknown")
        status      — TEXT ("running" / "sleeping" / "zombie" / etc.)
    """
    conn = _get_connection()
    cursor = conn.cursor()
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
    conn.commit()
    conn.close()


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
