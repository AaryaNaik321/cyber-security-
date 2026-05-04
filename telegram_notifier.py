import os
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

_BASE = Path(__file__).resolve().parent
load_dotenv(_BASE / "backend" / ".env")
load_dotenv(_BASE / ".env")

TELEGRAM_BOT_TOKEN = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
TELEGRAM_CHAT_ID = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()


def send_threat_alert(threat_result: dict):
    """
    Sends a formatted threat alert to Telegram.
    Only sends if a real threat is detected (not clean/safe).
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "not configured"

    severity = threat_result.get("severity", "Unknown")
    threat_name = threat_result.get("threat_name", "Unknown Threat")
    threat_category = threat_result.get("threat_category", "Unknown")
    confidence = threat_result.get("confidence", 0)
    what_it_does = threat_result.get("what_it_does", "")
    immediate_actions = threat_result.get("immediate_actions", [])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Severity emoji
    severity_emoji = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢"
    }.get(severity, "⚪")

    # Format immediate actions as numbered list
    actions_text = ""
    for i, action in enumerate(immediate_actions, 1):
        actions_text += f"  {i}. {action}\n"

    message = f"""
🛡️ *AI CYBER THREAT DETECTOR ALERT*
━━━━━━━━━━━━━━━━━━━━━━
{severity_emoji} *Severity:* {severity}
🎯 *Threat:* {threat_name}
📂 *Category:* {threat_category}
📊 *Confidence:* {confidence}%
🕐 *Detected At:* {timestamp}

📋 *What It Does:*
{what_it_does}

🚨 *Immediate Actions:*
{actions_text}
━━━━━━━━━━━━━━━━━━━━━━
⚡ _Sent by AI Cyber Threat Detector_
"""

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            return True, "Notification sent successfully"
        else:
            return False, f"Failed: {response.text}"
    except Exception as e:
        return False, str(e)


def send_no_threat_message():
    """Sends a clean/safe message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"""
✅ *AI CYBER THREAT DETECTOR*
━━━━━━━━━━━━━━━━━━━━━━
🟢 *Status: NO THREAT DETECTED*
🕐 *Scanned At:* {timestamp}

The submitted data appears clean.
No suspicious activity found.
━━━━━━━━━━━━━━━━━━━━━━
⚡ _Sent by AI Cyber Threat Detector_
"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except:
        return False
