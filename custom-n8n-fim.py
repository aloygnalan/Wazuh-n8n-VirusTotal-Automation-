#!/usr/bin/env python3
# ==========================================================
# Custom Wazuh \u2192 n8n integration for FIM (File Integrity)
# Sends alert JSON to n8n Webhook via POST method
# ==========================================================

import sys
import json
import requests
import os

LOG_FILE = "/var/ossec/logs/integrations.log"

def log_message(msg):
    """Write debug info to Wazuh's integration log"""
    with open(LOG_FILE, "a") as log:
        log.write(f"[custom-n8n-fim] {msg}\n")

def main():
    # Wazuh passes these: <alert_file> <user> <hook_url>
    if len(sys.argv) < 4:
        log_message("\u274c Missing arguments. Usage: custom-n8n-fim.py <alert_file> <user> <hook_url>")
        sys.exit(1)

    alert_file = sys.argv[1]
    hook_url = sys.argv[3]

    # -------------------------------------
    # Read the live alert (not full alerts.json)
    # -------------------------------------
    try:
        with open(alert_file, "r") as f:
            content = f.read().strip()
            if not content:
                log_message("\u26a0\ufe0f No content in alert file.")
                return

            try:
                alert = json.loads(content)
            except json.JSONDecodeError:
                lines = content.splitlines()
                alert = json.loads(lines[-1])

    except Exception as e:
        log_message(f"Error reading alert file: {e}")
        return

    # -------------------------------------
    # Only forward FIM alerts
    # -------------------------------------
    rule = alert.get("rule", {})
    groups = rule.get("groups", [])
    if "syscheck" not in groups:
        log_message("Skipping non-FIM alert.")
        return

    # -------------------------------------
    # Extract key fields for readability
    # -------------------------------------
    agent = alert.get("agent", {})
    syscheck = alert.get("syscheck", {})

    payload = {
        "event": syscheck.get("event", ""),
        "path": syscheck.get("path", ""),
        "md5": syscheck.get("md5", ""),
        "sha1": syscheck.get("sha1", ""),
        "sha256": syscheck.get("sha256", ""),
        "size": syscheck.get("size", ""),
        "timestamp": alert.get("timestamp", ""),
        "agent": agent.get("name", "unknown"),
        "rule": rule,
        "full_alert": alert
    }

    # -------------------------------------
    # Send to n8n Webhook (POST)
    # -------------------------------------
    try:
        resp = requests.post(hook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            log_message(f"\u2705 FIM alert sent successfully to n8n. File={payload['path']}")
        else:
            log_message(f"\u26a0\ufe0f HTTP {resp.status_code} from n8n: {resp.text}")
    except Exception as e:
        log_message(f"Error sending alert to n8n: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log_message(f"Unexpected error: {e}")
        sys.exit(1)

