# 🧩 Wazuh–n8n–VirusTotal File Upload Automation

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
```
Add integration to /var/ossec/etc/ossec.conf:

```xml
<integration>
  <name>custom-n8n-fim</name>
  <hook_url>http://localhost:5678/webhook-test/wazuh-fim</hook_url>
  <level>5</level>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```
Restart Wazuh:

```bash
systemctl restart wazuh-manager
```
----

# 2️⃣ n8n Workflow Setup

Node Order:

Webhook Node

Execute Command Node

Code Node → Prepare Binary

HTTP Request Node → Upload file to VirusTotal

Wait Node (5 seconds)

IF Node → Check if status = completed

Code Node → Format summary + link

Gmail Node → Send SOC email
