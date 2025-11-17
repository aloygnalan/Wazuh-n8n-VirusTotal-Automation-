# 🧩 Wazuh n8n VirusTotal File Upload Automation

## 🔍 Project Overview

This project automates **real-time malware triage and alerting** by integrating:

> 🛡️ **Wazuh → n8n → VirusTotal → Gmail**

Unlike typical setups that only perform **hash lookups**,  
this workflow directly **uploads the actual suspicious file** detected by Wazuh’s File Integrity Monitoring (FIM)  
to **VirusTotal** for a fresh live scan.  

Once the scan completes, it automatically sends a **detailed SOC email report** containing:  
- File metadata  
- Detection summary  
- Verdict (Malicious / Suspicious / Clean)  
- Direct **VirusTotal GUI link** to the detection report.

---

## 🧩 Key Highlights

✅ **Direct file upload** to VirusTotal (not hash-based)  
✅ **Automatic trigger** from Wazuh FIM alerts  
✅ **Dynamic wait loop** for VirusTotal scan completion  
✅ **Structured Gmail alert** to SOC analysts  
✅ Fully **modular**, extendable, and self-contained  
✅ Safe and tested using **EICAR test file**

---

## 🧱 Architecture

<img width="1773" height="533" alt="image" src="https://github.com/user-attachments/assets/c0373c83-2b12-4b35-95d3-08fb4aead4ef" />

---

## ⚙️ Workflow Summary

| Step | Component | Description |
|------|------------|-------------|
| 1️⃣ | **Wazuh FIM** | Detects file creation/modification and triggers integration. |
| 2️⃣ | **Python Script (`custom-n8n-fim.py`)** | Parses alert JSON and sends file details to n8n webhook. |
| 3️⃣ | **n8n Webhook Node** | Receives Wazuh alert payload. |
| 4️⃣ | **Execute Command Node** | Reads the file and encodes it in base64. |
| 5️⃣ | **Prepare Binary Node** | Converts base64 into binary for VirusTotal upload. |
| 6️⃣ | **HTTP Request (VirusTotal Upload)** | Uploads the actual file to VirusTotal `/api/v3/files`. |
| 7️⃣ | **Wait + IF Nodes** | Poll until VirusTotal status = `completed`. |
| 8️⃣ | **Code Node** | Extracts results and generates GUI report link. |
| 9️⃣ | **Gmail Node** | Sends professional alert email to SOC. |

----

## 📷 Output

<img width="1323" height="609" alt="image" src="https://github.com/user-attachments/assets/43ffc5b6-bd49-42f8-9a6d-690f1bafb2dc" />

---

## ⚙️ Setup Guide

# 1️⃣ Wazuh Integration

Copy the scripts to Wazuh Manager:

```bash
cp custom-n8n-fim /var/ossec/integrations/
cp custom-n8n-fim.py /var/ossec/integrations/
chmod +x /var/ossec/integrations/custom-n8n-fim
chmod +x /var/ossec/integrations/custom-n8n-fim.py
sudo chown root:wazuh custom-n8n-fim
sudo chown root:wazuh custom-n8n-fim.py
```
Add integration to /var/ossec/etc/ossec.conf:

```xml
<integration>
  <name>custom-n8n-fim</name>
  <hook_url>http://localhost:5678/webhook-test/wazuh-fim</hook_url>
  <rule_id>554</rule_id>
  <alert_format>json</alert_format>
</integration>
```
Restart Wazuh:

```bash
systemctl restart wazuh-manager
```
----

# 2️⃣ Extract File Details

javascript:

```javascript
// All useful data is inside the "body" object
const body = $json.body || {};

const filePath = body.path || body.full_alert?.syscheck?.path || "";
const md5 = body.md5 || body.full_alert?.syscheck?.md5_after || "";
const sha256 = body.sha256 || body.full_alert?.syscheck?.sha256_after || "";
const event = body.event || body.full_alert?.syscheck?.event || "";
const agentName = body.agent || body.full_alert?.agent?.name || "unknown";
const agentIp = body.full_alert?.agent?.ip || "192.168.122.202";

return [{
  json: {
    file_path: filePath,
    md5: md5,
    sha256: sha256,
    agent: agentName,
    agent_ip: agentIp,
    agent_user: "kali", // your SSH user
    event: event,
    timestamp: body.timestamp || body.full_alert?.timestamp || ""
  }
}];
```

---

# 3️⃣ Execute Command Node

On Agent Side Configuration:

```bash
# sudo tee /usr/local/bin/n8n_read_root_file > /dev/null <<'SH'  
#!/bin/bash                                                
# ==========================================
# n8n_read_root_file
# Safely output a /root file as base64          
# Usage: n8n_read_root_file /root/filename
# ==========================================

REQUESTED="$1"

# Allow only files under /root/
case "$REQUESTED" in
  /root/*)
    if [ -f "$REQUESTED" ] && [ -r "$REQUESTED" ]; then
      base64 -w 0 "$REQUESTED"
      exit 0
    else  
      echo "__ERROR__NOT_READABLE__"
      exit 2
    fi    
    ;;
  *)  
    echo "__ERROR__INVALID_PATH__"
    exit 3
    ;;  
esac
SH

sudo chmod 750 /usr/local/bin/n8n_read_root_file
sudo chown root:root /usr/local/bin/n8n_read_root_file
```
```bash 
sudo tee /etc/sudoers.d/n8n_read_root_file > /dev/null <<'SUDO'
kali ALL=(root) NOPASSWD: /usr/local/bin/n8n_read_root_file
SUDO                                        

sudo chmod 440 /etc/sudoers.d/n8n_read_root_file
```
n8n Configuration:

In Command Execution Node:

```command
/root/scripts/n8n_read_root_file.sh {{$json["file_path"]}}
```
---

# 4️⃣ Prepare Binary for VirusTotal

Javascript:
```javascript
const stdout = $json["stdout"] ? $json["stdout"].trim() : "";

if (!stdout) {
  throw new Error("No base64 data from SSH node");
}

// Derive filename from path
const filename = $json["file_path"]
  ? $json["file_path"].split("/").pop()
  : "suspicious.bin";

// Return binary item for VirusTotal upload
return [
  {
    json: {
      file_path: $json["file_path"],
      filename: filename
    },
    binary: {
      file: {
        data: stdout,
        fileName: filename,
        mimeType: "application/octet-stream"
      }
    }
  }
];

```

---
# 5️⃣ Upload File to VirusTotal
<img width="472" height="754" alt="image" src="https://github.com/user-attachments/assets/3275cc2e-f7b8-4bc3-aab8-152e46636608" />
---

# 6️⃣ Check Analysis Status:
<img width="477" height="661" alt="image" src="https://github.com/user-attachments/assets/e538e459-b190-4673-bc26-4040910e0afa" />

---

# 7️⃣ Build Scan Summary:
javascript:
```javascript 
// Input: VirusTotal analysis JSON in $json
const vt = $json["data"] || {};
const attrs = vt.attributes || {};
const stats = attrs.stats || {};
const results = attrs.results || {};
const fileInfo = $json["meta"]?.file_info || {};
const vtLink = vt.links?.item || "";

// Extract top 3 engines that flagged the file
const flaggedEngines = Object.entries(results)
  .filter(([engine, data]) => data.category && data.category !== "undetected")
  .map(([engine, data]) => ({
    engine: data.engine_name,
    category: data.category,
    result: data.result
  }))
  .slice(0, 3); // Top 3

// Define overall verdict
let verdict = "Clean";
if (stats.malicious > 0) verdict = "Malicious";
else if (stats.suspicious > 0) verdict = "Suspicious";

// Build structured summary
const summary = {
  file_name: fileInfo.name || "Unknown",
  sha256: fileInfo.sha256 || "",
  md5: fileInfo.md5 || "",
  size: `${fileInfo.size || 0} bytes`,
  status: attrs.status || "unknown",
  verdict,
  malicious_count: stats.malicious || 0,
  suspicious_count: stats.suspicious || 0,
  undetected_count: stats.undetected || 0,
  report_link: vtLink
};

// Output for Gmail
return [{
  json: {
    summary,
    flaggedEngines,
  }
}];

```
# 8️⃣ Send Alert Via Mail
