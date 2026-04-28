"""
app.py — Flask Application Entry Point for Suspicious Process Monitor
=======================================================================
Serves the dashboard UI and exposes REST API endpoints for process data,
system stats, flagged event logs, CSV export, and runtime config updates.

Endpoints (from DESIGN.md):
    GET  /                → Render the dashboard HTML
    GET  /api/processes   → JSON list of all processes (auto-logs flagged)
    GET  /api/flagged     → JSON list of recent flagged events from SQLite
    GET  /api/system      → JSON system CPU + RAM stats
    GET  /api/export/csv  → Download flagged log history as CSV file
    POST /api/config      → Update CPU/RAM thresholds at runtime
"""

import os
import csv
import io
from datetime import datetime

from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS

import config
from database import init_db, log_flagged_process, get_recent_flagged, get_all_flagged, clear_logs
from monitor import get_all_processes, get_system_stats

# ── Flask App Setup ───────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# Ensure required directories exist
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)
os.makedirs(config.EXPORT_PATH, exist_ok=True)

# Initialize the SQLite database schema on startup
init_db()


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE: Dashboard Page
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    """Render the main dashboard HTML page."""
    return render_template("index.html", poll_interval=config.POLL_INTERVAL_MS)


# ──────────────────────────────────────────────────────────────────────────────
# API: All Running Processes
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/processes", methods=["GET"])
def api_processes():
    """
    Return a JSON array of every running process with flagging status.
    Automatically logs any flagged processes to the SQLite database.
    """
    processes = get_all_processes()

    # Auto-log flagged processes to SQLite
    for proc in processes:
        if proc.get("flagged"):
            log_flagged_process(proc)

    return jsonify(processes)


# ──────────────────────────────────────────────────────────────────────────────
# API: Recent Flagged Events (from SQLite log)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/flagged", methods=["GET"])
def api_flagged():
    """Return the 20 most recent flagged process events from the database."""
    flagged = get_recent_flagged(limit=20)
    return jsonify(flagged)


# ──────────────────────────────────────────────────────────────────────────────
# API: System-Wide Stats (CPU + RAM)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/system", methods=["GET"])
def api_system():
    """Return overall system CPU percentage and memory statistics."""
    stats = get_system_stats()
    return jsonify(stats)


# ──────────────────────────────────────────────────────────────────────────────
# API: Export Flagged Logs as CSV
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/export/csv", methods=["GET"])
def api_export_csv():
    """
    Generate a CSV file from all flagged process records in the database
    and return it as a downloadable response.
    Also saves a copy to the exports/ directory.
    """
    flagged = get_all_flagged()

    # Build the CSV in-memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "timestamp", "pid", "name", "cpu_percent",
        "mem_mb", "exe_path", "reason", "status"
    ])
    writer.writeheader()
    for row in flagged:
        writer.writerow(row)

    csv_content = output.getvalue()

    # Save a copy to exports/ directory
    filename = f"flagged_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(config.EXPORT_PATH, filename)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        f.write(csv_content)

    # Return as downloadable response
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ──────────────────────────────────────────────────────────────────────────────
# API: Update Configuration (Thresholds)
# ──────────────────────────────────────────────────────────────────────────────
@app.route("/api/config", methods=["POST"])
def api_config():
    """
    Accept a JSON body to update CPU and/or RAM thresholds at runtime.

    Expected JSON body (all fields optional):
        {
            "cpu_threshold": 80,
            "mem_threshold_mb": 600
        }

    Returns the currently active configuration.
    """
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


# ──────────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Suspicious Process Monitor")
    print("  Dashboard: http://localhost:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG_MODE)
