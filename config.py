"""
config.py — Central Configuration for Suspicious Process Monitor
=================================================================
Stores all tunable thresholds, file paths, SMTP email settings, and
application settings. Values can be overridden via environment variables
or updated at runtime via the POST /api/config and /api/alerts/config endpoints.
"""

import os

# ─── Helper ────────────────────────────────────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env(key, default=""):
    """Read an environment variable with a fallback default."""
    return os.environ.get(key, default)


# ─── Process Flagging Thresholds (Dashboard) ──────────────────────────────────
# Any process exceeding these thresholds will be flagged on the dashboard.
CPU_THRESHOLD = 70          # Flag processes using more than this CPU %
MEM_THRESHOLD_MB = 500      # Flag processes using more than this many MB of RAM

# ─── Frontend Polling ─────────────────────────────────────────────────────────
POLL_INTERVAL_MS = 5000     # Dashboard auto-refresh interval in milliseconds

# ─── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(_BASE_DIR, "logs", "flagged.db")

# ─── CSV Export ────────────────────────────────────────────────────────────────
EXPORT_PATH = os.path.join(_BASE_DIR, "exports")

# ─── Flask Settings ───────────────────────────────────────────────────────────
DEBUG_MODE = True
SECRET_KEY = _env("SECRET_KEY", "super-secret-key-change-in-production")


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL ALERT SYSTEM CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# ─── SMTP Email Settings ──────────────────────────────────────────────────────
# Configure via environment variables or the dashboard UI.
# By default, email alerts are DISABLED until SMTP is configured.
SMTP_SERVER = _env("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(_env("SMTP_PORT", "587"))
SMTP_USE_TLS = _env("SMTP_USE_TLS", "true").lower() == "true"

# HARDCODED SENDER CREDENTIALS
EMAIL_SENDER = "ahmedaqib152@gmail.com"
EMAIL_PASSWORD = "pthm xjce kekk zwas" # TODO: Update this with the real app password

EMAIL_RECIPIENTS = [r.strip() for r in _env("EMAIL_RECIPIENTS", "").split(",") if r.strip()]
EMAIL_ALERTS_ENABLED = _env("EMAIL_ALERTS_ENABLED", "false").lower() == "true"

# ─── Alert Thresholds (separate from dashboard thresholds) ────────────────────
# These thresholds control when EMAIL ALERTS are sent, not dashboard flagging.
ALERT_CPU_THRESHOLD = 80            # CPU % to trigger email alert
ALERT_CPU_SUSTAIN_SECONDS = 30      # Must exceed threshold for this many seconds
ALERT_MEM_THRESHOLD_MB = 500        # Memory in MB to trigger email alert
ALERT_MEM_PERCENT_THRESHOLD = 60    # % of total system RAM to trigger email alert

# ─── Suspicious Path Patterns ─────────────────────────────────────────────────
# Processes running from these directories are flagged as suspicious.
# Matched case-insensitively against the full exe_path.
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "/temp/",
    "/tmp/",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "/downloads/",
]

# ─── Suspicious Name Patterns ─────────────────────────────────────────────────
# Regex patterns to detect fake system-like process names.
# Each pattern is tested against the process name (case-insensitive).
SUSPICIOUS_NAME_PATTERNS = [
    r"^svchost\d+\.exe$",          # svchost32.exe, svchost64.exe
    r"^csrss\d+\.exe$",            # csrss32.exe
    r"^lsass\d+\.exe$",            # lsass32.exe
    r"^explorer\d+\.exe$",         # explorer32.exe
    r"^services\d+\.exe$",         # services32.exe
    r"^system\d+\.exe$",           # system32.exe (process, not folder)
    r"^winlogon\d+\.exe$",         # winlogon32.exe
    r".*_update\.exe$",            # chrome_update.exe, firefox_update.exe
    r".*_updater\.exe$",           # chrome_updater.exe
    r".*_helper\.exe$",            # suspicious helpers
    r"^svch0st\.exe$",             # typosquat: zero instead of 'o'
    r"^cs[r]?ss\.exe$",            # not flagged — real csrss; kept for doc
    r"^rundl132\.exe$",            # typosquat: '1' instead of 'l'
    r"^[a-z]{15,}\.exe$",          # very long random lowercase names (15+ chars)
    r"^[a-f0-9]{8,}\.exe$",        # hex-named executables (malware dropper)
]

# ─── Process Burst Detection ──────────────────────────────────────────────────
BURST_THRESHOLD = 20        # Max new processes allowed in the burst window
BURST_WINDOW_SECONDS = 60   # Sliding window duration (seconds)

# ─── Alert Cooldown ───────────────────────────────────────────────────────────
ALERT_COOLDOWN_SECONDS = 300    # 5 minutes — do not re-alert same PID+type

# ─── Alert Monitor Interval ───────────────────────────────────────────────────
ALERT_SCAN_INTERVAL = 10    # Background scan runs every N seconds

# ─── Daily Digest ─────────────────────────────────────────────────────────────
DAILY_DIGEST_HOUR = 8       # Send daily digest at this hour (24h format)
