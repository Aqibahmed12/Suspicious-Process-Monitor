"""
config.py — Central Configuration for Suspicious Process Monitor
=================================================================
Stores all tunable thresholds, file paths, and application settings.
These values are loaded at startup and can be modified at runtime
via the POST /api/config endpoint.
"""

import os

# ─── Process Flagging Thresholds ───────────────────────────────────────────────
# Any process exceeding these thresholds will be flagged on the dashboard.

CPU_THRESHOLD = 70          # Flag processes using more than this CPU %
MEM_THRESHOLD_MB = 500      # Flag processes using more than this many MB of RAM

# ─── Frontend Polling ─────────────────────────────────────────────────────────
POLL_INTERVAL_MS = 5000     # Dashboard auto-refresh interval in milliseconds

# ─── Database ──────────────────────────────────────────────────────────────────
# SQLite database path for storing flagged process events.
# The 'logs/' directory is created automatically at startup.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "flagged.db")

# ─── CSV Export ────────────────────────────────────────────────────────────────
# Directory where exported CSV reports are written.
# The 'exports/' directory is created automatically at startup.
EXPORT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exports")

# ─── Flask Settings ───────────────────────────────────────────────────────────
DEBUG_MODE = True
