"""
alert_monitor.py — Background Alert Monitor Thread
====================================================
Spawns a daemon thread that runs the detection engine every
ALERT_SCAN_INTERVAL seconds, applies cooldown logic, logs alerts
to SQLite, sends email notifications, and handles the daily digest.

Usage:
    from alert_monitor import start_alert_monitor
    start_alert_monitor()  # Call once at app startup
"""

import time
import logging
import threading
from datetime import datetime, timedelta

import config
from alert_engine import run_detection_scan
from cooldown import is_on_cooldown, record_alert, cleanup_stale
from database import log_email_alert, get_alerts_since
from email_service import send_alert_email, send_daily_digest

logger = logging.getLogger(__name__)

# ─── State ────────────────────────────────────────────────────────────────────
_monitor_thread = None
_monitor_running = False
_last_digest_date = None  # Track which date the last digest was sent for


def start_alert_monitor():
    """
    Start the background alert monitoring thread.
    Safe to call multiple times — only one thread will be created.

    In Flask debug mode (with reloader), the monitor only starts in the
    child process to avoid double-spawning.
    """
    global _monitor_thread, _monitor_running

    if _monitor_running:
        logger.debug("Alert monitor already running — skipping start.")
        return

    _monitor_running = True
    _monitor_thread = threading.Thread(
        target=_monitor_loop,
        name="AlertMonitor",
        daemon=True,  # Auto-stops when Flask exits
    )
    _monitor_thread.start()
    logger.info("Alert monitor thread started (interval: %ds)", config.ALERT_SCAN_INTERVAL)


def stop_alert_monitor():
    """Signal the monitor thread to stop gracefully."""
    global _monitor_running
    _monitor_running = False
    logger.info("Alert monitor stop requested.")


def is_monitor_running() -> bool:
    """Check if the alert monitor thread is active."""
    return _monitor_running and _monitor_thread is not None and _monitor_thread.is_alive()


# ─── Main Loop ────────────────────────────────────────────────────────────────

def _monitor_loop():
    """
    The core monitoring loop. Runs continuously until _monitor_running is False.

    Each iteration:
      1. Runs all 7 detection rules via run_detection_scan()
      2. For each alert, checks cooldown and processes accordingly
      3. Cleans up stale cooldown entries
      4. Checks if it's time to send the daily digest
      5. Sleeps for ALERT_SCAN_INTERVAL seconds
    """
    global _last_digest_date

    logger.info("Alert monitor loop starting...")

    while _monitor_running:
        try:
            # ── Step 1: Run detection scan ────────────────────────────────
            alerts = run_detection_scan()

            # ── Step 2: Process each alert ────────────────────────────────
            for alert in alerts:
                pid = alert.get("pid", 0)
                alert_type = alert.get("alert_type", "")

                # Check cooldown — skip if recently alerted
                if is_on_cooldown(pid, alert_type):
                    continue

                # Send email (if enabled)
                email_sent = send_alert_email(alert)

                # Log to database regardless of email success
                log_email_alert(alert, email_sent=email_sent)

                # Record in cooldown cache
                record_alert(pid, alert_type)

                severity = alert.get("severity", "INFO")
                name = alert.get("name", "")
                logger.info(
                    "[%s] %s alert for '%s' (PID %d) — email %s",
                    severity, alert_type, name, pid,
                    "sent" if email_sent else "skipped"
                )

            # ── Step 3: Cleanup stale cooldowns ───────────────────────────
            cleanup_stale()

            # ── Step 4: Daily digest check ────────────────────────────────
            _check_daily_digest()

        except Exception as e:
            logger.error("Alert monitor error: %s", e, exc_info=True)

        # ── Step 5: Sleep ─────────────────────────────────────────────────
        # Sleep in small increments so stop requests are responsive
        for _ in range(config.ALERT_SCAN_INTERVAL * 2):
            if not _monitor_running:
                break
            time.sleep(0.5)

    logger.info("Alert monitor loop stopped.")


def _check_daily_digest():
    """
    Send a daily digest email at the configured hour if one hasn't
    been sent today already.
    """
    global _last_digest_date

    now = datetime.now()
    today = now.date()

    # Only send at the configured hour
    if now.hour != config.DAILY_DIGEST_HOUR:
        return

    # Don't send more than once per day
    if _last_digest_date == today:
        return

    # Gather all alerts from the last 24 hours
    since = (now - timedelta(hours=24)).isoformat()
    alerts = get_alerts_since(since)

    if not alerts:
        logger.debug("Daily digest: no alerts in last 24h — skipping.")
        _last_digest_date = today
        return

    success = send_daily_digest(alerts)
    if success:
        logger.info("Daily digest sent with %d alerts.", len(alerts))
    else:
        logger.warning("Daily digest send failed.")

    # Mark as sent regardless to avoid retry spam
    _last_digest_date = today
