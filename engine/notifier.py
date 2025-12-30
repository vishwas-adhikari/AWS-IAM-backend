import requests
import os
from dotenv import load_dotenv

load_dotenv()

def send_telegram_report(scan_obj):
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    
    if not token or not chat_id:
        print("Telegram configuration missing. Skipping notification.")
        return

    # 1. Determine Header Emoji
    status_emoji = "🔴" if scan_obj.risk_score > 50 else "🟢"
    
    # 2. Get Immediate Attention Alerts (Top 3 Critical/High)
    immediate_alerts = scan_obj.findings.filter(severity__in=['CRITICAL', 'HIGH'])[:3]
    alert_text = ""
    for alert in immediate_alerts:
        emoji = "🔥" if alert.severity == "CRITICAL" else "⚠️"
        alert_text += f"{emoji} *{alert.title}*\n   └ `{alert.affected_resource}`\n"
    
    if not alert_text:
        alert_text = "✅ No critical/high risks detected."

    # 3. Build the Markdown Message
    message = (
        f"{status_emoji} *IAM SECURITY SCAN REPORT*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"👤 *ACCOUNT DETAILS*\n"
        f"• ID: `{scan_obj.account_id}`\n"
        f"• Time: `{scan_obj.scan_time.strftime('%Y-%m-%d %H:%M')}`\n\n"
        
        f"📊 *STATISTICS*\n"
        f"• Risk Score: `{scan_obj.risk_score}/100` (Lower is better)\n"
        f"• Total Users: {scan_obj.total_users}\n"
        f"• Total Roles: {scan_obj.total_roles}\n\n"
        
        f"🚨 *IMMEDIATE ATTENTION*\n"
        f"{alert_text}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"👉 [Open Dashboard](http://localhost:5173/dashboard)"
    )

    # 4. Send to Telegram API
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=8)
        if response.status_code != 200:
            print(f"Telegram API Error: {response.text}")
    except Exception as e:
        print(f"Failed to connect to Telegram: {e}")