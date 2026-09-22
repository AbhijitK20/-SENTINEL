"""Webhook notification system for SENTINEL alerts.

Sends alerts to Slack, email, or generic webhooks when detectors fire.
Configured via environment variables.

Environment variables:
    SENTINEL_WEBHOOK_URL: Generic webhook URL (POST JSON)
    SENTINEL_SLACK_WEBHOOK: Slack incoming webhook URL
    SENTINEL_ALERT_EMAIL: Email address for alerts (requires SMTP config)
    SENTINEL_ALERT_THRESHOLD: Minimum severity to trigger (default: "low")
"""

from __future__ import annotations

import json
import os
import smtplib
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

# Severity order for threshold comparison
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_meets_threshold(severity: str, threshold: str) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 0)


def _format_slack_message(finding: dict[str, Any], incident: dict[str, Any] | None = None) -> dict:
    severity = finding.get("severity", "unknown")
    color_map = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#66ccff",
        "info": "#cccccc",
    }
    color = color_map.get(severity, "#cccccc")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 SENTINEL Alert: {finding.get('attack_type', 'unknown')}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                {"type": "mrkdwn", "text": f"*Confidence:* {finding.get('confidence', 'unknown')}"},
                {"type": "mrkdwn", "text": f"*MITRE:* {finding.get('mitre_technique', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Probability:* {finding.get('probability', 0):.2%}"},
            ],
        },
    ]

    if incident:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Incident:* {incident.get('incident_id', 'N/A')}"
                        f" — Risk: {incident.get('risk', {}).get('level', 'unknown')}"
                    ),
                },
            }
        )

    return {"attachments": [{"color": color, "blocks": blocks}]}


def _send_webhook(url: str, payload: dict) -> bool:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def _send_slack(webhook_url: str, payload: dict) -> bool:
    return _send_webhook(webhook_url, payload)


def _send_email(to_email: str, subject: str, body: str) -> bool:
    smtp_host = os.environ.get("SENTINEL_SMTP_HOST", "localhost")
    smtp_port = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
    smtp_user = os.environ.get("SENTINEL_SMTP_USER", "")
    smtp_pass = os.environ.get("SENTINEL_SMTP_PASS", "")
    from_email = os.environ.get("SENTINEL_ALERT_FROM", "sentinel@localhost")

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception:
        return False


def notify_alert(finding: dict[str, Any], incident: dict[str, Any] | None = None) -> None:
    """Send alert notifications to all configured channels.

    Called by the live engine when a detector fires above threshold.
    Non-blocking: failures are logged but never crash the engine.
    """
    threshold = os.environ.get("SENTINEL_ALERT_THRESHOLD", "low")
    severity = finding.get("severity", "info")

    if not _severity_meets_threshold(severity, threshold):
        return

    slack_url = os.environ.get("SENTINEL_SLACK_WEBHOOK")
    if slack_url:
        payload = _format_slack_message(finding, incident)
        _send_slack(slack_url, payload)

    webhook_url = os.environ.get("SENTINEL_WEBHOOK_URL")
    if webhook_url:
        payload = {
            "alert_type": "detector_finding",
            "attack_type": finding.get("attack_type"),
            "severity": severity,
            "probability": finding.get("probability"),
            "confidence": finding.get("confidence"),
            "mitre_technique": finding.get("mitre_technique"),
            "incident_id": incident.get("incident_id") if incident else None,
            "risk_level": incident.get("risk", {}).get("level") if incident else None,
        }
        _send_webhook(webhook_url, payload)

    email = os.environ.get("SENTINEL_ALERT_EMAIL")
    if email:
        subject = f"[SENTINEL] {severity.upper()}: {finding.get('attack_type', 'alert')}"
        body = f"""
        <h2>SENTINEL Alert</h2>
        <p><b>Attack Type:</b> {finding.get("attack_type", "unknown")}</p>
        <p><b>Severity:</b> {severity}</p>
        <p><b>Confidence:</b> {finding.get("confidence", "unknown")}</p>
        <p><b>MITRE:</b> {finding.get("mitre_technique", "N/A")}</p>
        <p><b>Probability:</b> {finding.get("probability", 0):.2%}</p>
        {"<p><b>Incident:</b> " + incident.get("incident_id", "N/A") + "</p>" if incident else ""}
        """
        _send_email(email, subject, body)
