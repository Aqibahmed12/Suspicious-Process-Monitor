"""
app.py — Flask Application Entry Point for Suspicious Process Monitor
=======================================================================
Serves the dashboard UI and exposes REST API endpoints for process data,
system stats, flagged event logs, CSV export, runtime config updates,
and the email alert system.

Endpoints:
    GET  /                  → Render the dashboard HTML
    GET  /api/processes     → JSON list of all processes (auto-logs flagged)
    GET  /api/flagged       → JSON list of recent flagged events from SQLite
    GET  /api/system        → JSON system CPU + RAM stats
    GET  /api/export/csv    → Download flagged log history as CSV file
    POST /api/config        → Update CPU/RAM thresholds at runtime
    GET  /api/alerts        → JSON list of recent email alerts
    GET  /api/alerts/stats  → Alert severity counts
    POST /api/alerts/config → Update email/alert settings at runtime
    POST /api/alerts/test   → Send a test email
"""

import os
import csv
import io
import logging
import random
from functools import wraps
from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
from flask_cors import CORS

import config
from database import (
    init_db, log_flagged_process, get_recent_flagged,
    get_all_flagged, clear_logs,
    get_recent_alerts, get_alert_stats,
)
from monitor import get_all_processes, get_system_stats
from alert_monitor import start_alert_monitor, is_monitor_running
from email_service import send_test_email, send_otp_email

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ── Flask App Setup ───────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
app.secret_key = config.SECRET_KEY

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            if request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Ensure required directories exist
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)
os.makedirs(config.EXPORT_PATH, exist_ok=True)

# Initialize the SQLite database schema on startup
init_db()

# Start the background alert monitor thread
# Guard against double-start in Flask debug mode (reloader spawns child process)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not config.DEBUG_MODE:
    start_alert_monitor()


# ══════════════════════════════════════════════════════════════════════════════
# ORIGINAL ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    """Render the main dashboard HTML page."""
    return render_template("index.html", poll_interval=config.POLL_INTERVAL_MS)


# ══════════════════════════════════════════════════════════════════════════════
# LOGIN ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/login")
def login():
    """Render the OTP login page."""
    if session.get('authenticated'):
        return redirect(url_for('index'))
    return render_template("login.html")

@app.route("/api/login/send-otp", methods=["POST"])
def send_otp():
    """Generate and send an OTP."""
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = str(random.randint(100000, 999999))
    session['otp'] = otp
    session['otp_expiry'] = (datetime.now() + timedelta(minutes=5)).timestamp()
    
    success = send_otp_email(email, otp)
    if success:
        return jsonify({"status": "ok"})
    return jsonify({"error": "Failed to send email. Check SMTP config."}), 500

@app.route("/api/login/verify-otp", methods=["POST"])
def verify_otp():
    """Verify the submitted OTP."""
    data = request.get_json(silent=True) or {}
    submitted_otp = data.get("otp")
    
    stored_otp = session.get('otp')
    expiry = session.get('otp_expiry')
    
    if not stored_otp or not expiry:
        return jsonify({"error": "No OTP requested."}), 400
        
    if datetime.now().timestamp() > expiry:
        return jsonify({"error": "OTP has expired."}), 400
        
    if submitted_otp == stored_otp:
        session['authenticated'] = True
        session.pop('otp', None)
        session.pop('otp_expiry', None)
        return jsonify({"status": "ok"})
        
    return jsonify({"error": "Invalid OTP."}), 400


@app.route("/api/processes", methods=["GET"])
@login_required
def api_processes():
    """Return JSON array of every running process with flagging status."""
    processes = get_all_processes()
    for proc in processes:
        if proc.get("flagged"):
            log_flagged_process(proc)
    return jsonify(processes)


@app.route("/api/flagged", methods=["GET"])
@login_required
def api_flagged():
    """Return the 20 most recent flagged process events."""
    flagged = get_recent_flagged(limit=20)
    return jsonify(flagged)


@app.route("/api/system", methods=["GET"])
@login_required
def api_system():
    """Return overall system CPU percentage and memory statistics."""
    stats = get_system_stats()
    return jsonify(stats)


@app.route("/api/export/csv", methods=["GET"])
@login_required
def api_export_csv():
    """Generate and download flagged log history as CSV."""
    flagged = get_all_flagged()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "timestamp", "pid", "name", "cpu_percent",
        "mem_mb", "exe_path", "reason", "status"
    ])
    writer.writeheader()
    for row in flagged:
        writer.writerow(row)

    csv_content = output.getvalue()

    filename = f"flagged_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(config.EXPORT_PATH, filename)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        f.write(csv_content)

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/config", methods=["POST"])
@login_required
def api_config():
    """Update CPU/RAM dashboard thresholds at runtime."""
    data = request.get_json(silent=True) or {}

    if "cpu_threshold" in data:
        try:
            config.CPU_THRESHOLD = float(data["cpu_threshold"])
        except (ValueError, TypeError):
            pass

    if "mem_threshold_mb" in data:
        try:
            config.MEM_THRESHOLD_MB = float(data["mem_threshold_mb"])
        except (ValueError, TypeError):
            pass

    return jsonify({
        "status": "ok",
        "cpu_threshold": config.CPU_THRESHOLD,
        "mem_threshold_mb": config.MEM_THRESHOLD_MB,
        "poll_interval_ms": config.POLL_INTERVAL_MS,
    })


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL ALERT SYSTEM ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/alerts", methods=["GET"])
@login_required
def api_alerts():
    """Return recent email alerts (last 50)."""
    alerts = get_recent_alerts(limit=50)
    return jsonify(alerts)


@app.route("/api/alerts/stats", methods=["GET"])
@login_required
def api_alert_stats():
    """Return alert severity counts and statistics."""
    stats = get_alert_stats()
    stats["monitor_running"] = is_monitor_running()
    stats["email_enabled"] = config.EMAIL_ALERTS_ENABLED
    return jsonify(stats)


@app.route("/api/alerts/config", methods=["POST"])
@login_required
def api_alerts_config():
    """
    Update email alert settings at runtime.

    Accepts JSON body with any of:
        smtp_server, smtp_port, smtp_use_tls,
        email_sender, email_password, email_recipients,
        email_alerts_enabled,
        alert_cpu_threshold, alert_cpu_sustain_seconds,
        alert_mem_threshold_mb, alert_mem_percent_threshold
    """
    data = request.get_json(silent=True) or {}

    # SMTP settings
    if "smtp_server" in data:
        config.SMTP_SERVER = str(data["smtp_server"])
    if "smtp_port" in data:
        try:
            config.SMTP_PORT = int(data["smtp_port"])
        except (ValueError, TypeError):
            pass
    if "smtp_use_tls" in data:
        config.SMTP_USE_TLS = bool(data["smtp_use_tls"])
    if "email_recipients" in data:
        val = data["email_recipients"]
        if isinstance(val, list):
            config.EMAIL_RECIPIENTS = [r.strip() for r in val if r.strip()]
        elif isinstance(val, str):
            config.EMAIL_RECIPIENTS = [r.strip() for r in val.split(",") if r.strip()]
    if "email_alerts_enabled" in data:
        config.EMAIL_ALERTS_ENABLED = bool(data["email_alerts_enabled"])

    # Alert thresholds
    if "alert_cpu_threshold" in data:
        try:
            config.ALERT_CPU_THRESHOLD = float(data["alert_cpu_threshold"])
        except (ValueError, TypeError):
            pass
    if "alert_cpu_sustain_seconds" in data:
        try:
            config.ALERT_CPU_SUSTAIN_SECONDS = int(data["alert_cpu_sustain_seconds"])
        except (ValueError, TypeError):
            pass
    if "alert_mem_threshold_mb" in data:
        try:
            config.ALERT_MEM_THRESHOLD_MB = float(data["alert_mem_threshold_mb"])
        except (ValueError, TypeError):
            pass
    if "alert_mem_percent_threshold" in data:
        try:
            config.ALERT_MEM_PERCENT_THRESHOLD = float(data["alert_mem_percent_threshold"])
        except (ValueError, TypeError):
            pass

    return jsonify({
        "status": "ok",
        "email_alerts_enabled": config.EMAIL_ALERTS_ENABLED,
        "smtp_server": config.SMTP_SERVER,
        "smtp_port": config.SMTP_PORT,
        "smtp_use_tls": config.SMTP_USE_TLS,
        "email_sender": config.EMAIL_SENDER,
        "email_recipients": config.EMAIL_RECIPIENTS,
        "alert_cpu_threshold": config.ALERT_CPU_THRESHOLD,
        "alert_cpu_sustain_seconds": config.ALERT_CPU_SUSTAIN_SECONDS,
        "alert_mem_threshold_mb": config.ALERT_MEM_THRESHOLD_MB,
        "alert_mem_percent_threshold": config.ALERT_MEM_PERCENT_THRESHOLD,
    })


@app.route("/api/alerts/test", methods=["POST"])
@login_required
def api_alerts_test():
    """Send a test email to verify SMTP configuration."""
    success, message = send_test_email()
    return jsonify({
        "status": "ok" if success else "error",
        "message": message,
    }), 200 if success else 500


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Suspicious Process Monitor")
    print("  Dashboard: http://localhost:5000")
    print("  Email Alerts: " + ("ENABLED" if config.EMAIL_ALERTS_ENABLED else "DISABLED"))
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG_MODE)
