"""
email_service.py — SMTP Email Service
=======================================
Composes and sends alert emails (HTML + plain text) and daily digest
summaries via SMTP. Uses only Python built-in modules (smtplib, email).
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

import config

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def send_otp_email(target_email: str, otp: str) -> bool:
    """
    Send an OTP code for login verification.
    """
    if not config.EMAIL_SENDER:
        logger.warning("Email sender not configured.")
        return False

    subject = f"Your Login OTP: {otp}"
    
    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;
                background:#0f172a;color:#e2e8f0;padding:30px;border-radius:12px;">
        <h2 style="color:#38bdf8;margin-top:0;">Login Verification</h2>
        <p>Please use the following OTP to log in to the Suspicious Process Monitor dashboard. This code will expire in 5 minutes.</p>
        <div style="background:#1e293b;padding:20px;border-radius:8px;text-align:center;margin:30px 0;">
            <span style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#e2e8f0;">{otp}</span>
        </div>
        <hr style="border-color:#334155;margin:20px 0;">
        <p style="color:#94a3b8;font-size:12px;">
            Suspicious Process Monitor &bull; Automated System
        </p>
    </div>
    """
    
    text_body = f"Login Verification\n\nPlease use the following OTP to log in: {otp}\nThis code will expire in 5 minutes."

    return _send_email(subject, html_body, text_body, recipients=[target_email])

def send_alert_email(alert: dict) -> bool:
    """
    Send a single alert email for a detected suspicious process.
    Composes both HTML and plain-text MIME parts.

    Args:
        alert: AlertEvent dict from alert_engine.

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not config.EMAIL_ALERTS_ENABLED:
        logger.debug("Email alerts disabled — skipping send.")
        return False

    if not config.EMAIL_SENDER or not config.EMAIL_RECIPIENTS:
        logger.warning("Email sender or recipients not configured.")
        return False

    severity = alert.get("severity", "INFO")
    name = alert.get("name", "Unknown")
    subject = f"\U0001f6a8 [{severity}] Suspicious Process Detected \u2014 {name}"

    html_body = _build_html_email(alert)
    text_body = _build_plaintext_email(alert)

    return _send_email(subject, html_body, text_body)


def send_daily_digest(alerts: list[dict]) -> bool:
    """
    Send a daily summary of all suspicious activity.

    Args:
        alerts: List of AlertEvent dicts from the last 24 hours.

    Returns:
        True if email sent successfully, False otherwise.
    """
    if not config.EMAIL_ALERTS_ENABLED:
        return False
    if not config.EMAIL_SENDER or not config.EMAIL_RECIPIENTS:
        return False

    today = datetime.now().strftime("%Y-%m-%d")
    subject = f"\U0001f4ca Daily Security Digest \u2014 {today} ({len(alerts)} alerts)"

    html_body = _build_digest_html(alerts, today)
    text_body = _build_digest_plaintext(alerts, today)

    return _send_email(subject, html_body, text_body)


def send_test_email() -> tuple[bool, str]:
    """
    Send a test email to verify SMTP configuration.

    Returns:
        (success: bool, message: str)
    """
    if not config.EMAIL_SENDER or not config.EMAIL_RECIPIENTS:
        return False, "Email sender or recipients not configured."

    subject = "\u2705 Suspicious Process Monitor \u2014 Test Email"
    html = """
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;
                background:#0f172a;color:#e2e8f0;padding:30px;border-radius:12px;">
        <h2 style="color:#38bdf8;margin-top:0;">\u2705 SMTP Connection Successful</h2>
        <p>This is a test email from <strong>Suspicious Process Monitor</strong>.</p>
        <p>Your email alert system is configured correctly and ready to send alerts.</p>
        <hr style="border-color:#334155;margin:20px 0;">
        <p style="color:#94a3b8;font-size:12px;">
            Server: {server}:{port} | TLS: {tls} | Sender: {sender}
        </p>
    </div>
    """.format(
        server=config.SMTP_SERVER, port=config.SMTP_PORT,
        tls=config.SMTP_USE_TLS, sender=config.EMAIL_SENDER,
    )
    text = (
        "SMTP Connection Successful\n\n"
        "This is a test email from Suspicious Process Monitor.\n"
        f"Server: {config.SMTP_SERVER}:{config.SMTP_PORT}\n"
    )

    try:
        # Temporarily enable for test
        original = config.EMAIL_ALERTS_ENABLED
        config.EMAIL_ALERTS_ENABLED = True
        success = _send_email(subject, html, text)
        config.EMAIL_ALERTS_ENABLED = original
        if success:
            return True, "Test email sent successfully."
        return False, "Failed to send test email."
    except Exception as e:
        return False, str(e)


# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL COMPOSITION
# ═══════════════════════════════════════════════════════════════════════════════

def _build_html_email(alert: dict) -> str:
    """Render an HTML alert email with a styled table."""
    sev = alert.get("severity", "INFO")
    sev_color = {"CRITICAL": "#ef4444", "WARNING": "#f97316", "INFO": "#38bdf8"}.get(sev, "#38bdf8")

    rows = [
        ("Alert Type", alert.get("alert_type", "")),
        ("Severity", f'<span style="color:{sev_color};font-weight:bold;">{sev}</span>'),
        ("Process Name", alert.get("name", "")),
        ("PID", str(alert.get("pid", ""))),
        ("CPU Usage", f"{alert.get('cpu_percent', 0)}%"),
        ("Memory Usage", f"{alert.get('mem_mb', 0)} MB"),
        ("Executable Path", alert.get("exe_path", "N/A")),
        ("Start Time", alert.get("start_time", "N/A")),
        ("Status", alert.get("status", "")),
        ("User", alert.get("user", "N/A")),
        ("Reason", alert.get("reason", "")),
        ("Recommended Action", f'<em>{alert.get("recommended_action", "")}</em>'),
    ]

    table_rows = ""
    for i, (label, value) in enumerate(rows):
        bg = "#1e293b" if i % 2 == 0 else "#0f172a"
        table_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:10px 14px;color:#94a3b8;font-weight:600;'
            f'border-bottom:1px solid #334155;width:180px;">{label}</td>'
            f'<td style="padding:10px 14px;color:#e2e8f0;'
            f'border-bottom:1px solid #334155;">{value}</td></tr>'
        )

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:0 auto;
                background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden;
                border:1px solid #334155;">
        <div style="background:linear-gradient(135deg,#1e293b,#0f172a);
                    padding:24px 28px;border-bottom:2px solid {sev_color};">
            <h2 style="margin:0;color:{sev_color};font-size:18px;">
                \U0001f6a8 {sev} — Suspicious Process Detected
            </h2>
            <p style="margin:6px 0 0;color:#64748b;font-size:13px;">
                {alert.get("timestamp", "")}
            </p>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
            {table_rows}
        </table>
        <div style="padding:16px 28px;background:#1e293b;
                    border-top:1px solid #334155;">
            <p style="margin:0;color:#64748b;font-size:11px;">
                Suspicious Process Monitor &bull; Automated Alert System
            </p>
        </div>
    </div>
    """


def _build_plaintext_email(alert: dict) -> str:
    """Render a plain-text alert email."""
    lines = [
        f"{'='*50}",
        f"  SUSPICIOUS PROCESS ALERT — {alert.get('severity', 'INFO')}",
        f"{'='*50}",
        f"  Timestamp:    {alert.get('timestamp', '')}",
        f"  Alert Type:   {alert.get('alert_type', '')}",
        f"  Severity:     {alert.get('severity', '')}",
        f"  Process Name: {alert.get('name', '')}",
        f"  PID:          {alert.get('pid', '')}",
        f"  CPU Usage:    {alert.get('cpu_percent', 0)}%",
        f"  Memory:       {alert.get('mem_mb', 0)} MB",
        f"  Exe Path:     {alert.get('exe_path', 'N/A')}",
        f"  Start Time:   {alert.get('start_time', 'N/A')}",
        f"  Status:       {alert.get('status', '')}",
        f"  User:         {alert.get('user', 'N/A')}",
        f"  Reason:       {alert.get('reason', '')}",
        f"  Action:       {alert.get('recommended_action', '')}",
        f"{'='*50}",
    ]
    return "\n".join(lines)


def _build_digest_html(alerts: list[dict], date_str: str) -> str:
    """Render the daily digest as a styled HTML table."""
    # Count by severity
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for a in alerts:
        sev = a.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    alert_rows = ""
    for i, a in enumerate(alerts[:100]):  # Cap at 100 rows
        bg = "#1e293b" if i % 2 == 0 else "#0f172a"
        sev = a.get("severity", "INFO")
        sev_color = {"CRITICAL": "#ef4444", "WARNING": "#f97316"}.get(sev, "#38bdf8")
        ts = a.get("timestamp", "")[:19]  # Trim microseconds
        alert_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:6px 10px;border-bottom:1px solid #334155;font-size:12px;color:#94a3b8;">{ts}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #334155;font-size:12px;">{a.get("name","")}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #334155;font-size:12px;">{a.get("pid","")}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #334155;font-size:12px;">{a.get("alert_type","")}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #334155;font-size:12px;color:{sev_color};font-weight:bold;">{sev}</td>'
            f'</tr>'
        )

    return f"""
    <div style="font-family:Arial,sans-serif;max-width:700px;margin:0 auto;
                background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:hidden;
                border:1px solid #334155;">
        <div style="padding:24px 28px;border-bottom:1px solid #334155;">
            <h2 style="margin:0;color:#38bdf8;">\U0001f4ca Daily Security Digest — {date_str}</h2>
            <p style="margin:8px 0 0;color:#94a3b8;">
                Total Alerts: <strong>{len(alerts)}</strong> |
                <span style="color:#ef4444;">Critical: {counts['CRITICAL']}</span> |
                <span style="color:#f97316;">Warning: {counts['WARNING']}</span> |
                <span style="color:#38bdf8;">Info: {counts['INFO']}</span>
            </p>
        </div>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#1e293b;">
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase;">Time</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase;">Name</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase;">PID</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase;">Type</th>
                <th style="padding:8px 10px;text-align:left;color:#64748b;font-size:11px;text-transform:uppercase;">Severity</th>
            </tr>
            {alert_rows}
        </table>
        <div style="padding:16px 28px;background:#1e293b;border-top:1px solid #334155;">
            <p style="margin:0;color:#64748b;font-size:11px;">
                Suspicious Process Monitor &bull; Daily Digest
            </p>
        </div>
    </div>
    """


def _build_digest_plaintext(alerts: list[dict], date_str: str) -> str:
    """Render the daily digest as plain text."""
    lines = [
        f"{'='*60}",
        f"  DAILY SECURITY DIGEST — {date_str}",
        f"  Total Alerts: {len(alerts)}",
        f"{'='*60}", "",
    ]
    for a in alerts[:100]:
        ts = a.get("timestamp", "")[:19]
        lines.append(
            f"  [{a.get('severity','INFO')}] {ts} | "
            f"PID {a.get('pid','')} | {a.get('name','')} | "
            f"{a.get('alert_type','')}"
        )
    lines.append(f"\n{'='*60}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SMTP TRANSPORT
# ═══════════════════════════════════════════════════════════════════════════════

def _send_email(subject: str, html_body: str, text_body: str, recipients: list[str] = None) -> bool:
    """
    Send an email via SMTP with both HTML and plain-text parts.

    Returns:
        True on success, False on failure.
    """
    try:
        target_recipients = recipients or config.EMAIL_RECIPIENTS
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config.EMAIL_SENDER
        msg["To"] = ", ".join(target_recipients)

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        if config.SMTP_USE_TLS:
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT, timeout=15)
            server.ehlo()

        if config.EMAIL_PASSWORD:
            server.login(config.EMAIL_SENDER, config.EMAIL_PASSWORD)

        server.sendmail(config.EMAIL_SENDER, target_recipients, msg.as_string())
        server.quit()

        logger.info(f"Email sent: {subject}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        return False
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False
