#  Scripting and Automation for Threat Mitigation

A professional-grade scripting and automation toolkit designed to detect, analyze, and respond to cybersecurity threats in real-time using cross-platform scripting. This project empowers Security Operations Centers (SOCs), Incident Response (IR) teams, and threat analysts to reduce dwell time, enrich indicators of compromise (IOCs), and accelerate response using Python, Bash, and PowerShell.

<br> <br/>

## Project Overview

**Name:** Scripting and Automation for Threat Mitigation 

**Maintainer:** Itsme-crypto 

**License:** MIT 

**Status:** Active Development  

**Compatible OS:** Windows, Linux (Ubuntu/CentOS), macOS (for Python scripts)

<br> <br/>

## Description

This toolkit automates key components of security operations by leveraging custom scripts to:
- Detect malicious activity from logs and network data
- Quarantine or block infected endpoints and IPs
- Perform enrichment using threat intelligence APIs
- Automate responses using SOAR-compatible logic

It serves as a modular and extensible framework that can be integrated with firewalls, SIEMs, EDR platforms, and SOAR solutions.

<br> <br/>

## Table of Contents

1. [Project Objectives](#1️⃣-project-objectives)  
2. [Use Cases](#2️⃣-use-cases)  
3. [Architecture Overview](#3️⃣-architecture-overview)  
4. [Scripting Languages & Environments](#4️⃣-scripting-languages--environments)  
5. [Example Scripts](#5️⃣-example-scripts)  
6. [Integration Targets](#6️⃣-integration-targets)  
7. [Best Practices](#7️⃣-best-practices)  
8. [Deployment & Scheduling](#8️⃣-deployment--scheduling)  
9. [Logging & Monitoring](#9️⃣-logging--monitoring)  
10. [Future Enhancements](#🔟-future-enhancements)  
11. [Appendix](#📎-appendix)

<br> <br/>

## 1. Project Objectives

-  Automate detection of known indicators of compromise (IOCs)
-  Quarantine infected systems or block IPs using firewall rules
-  Enrich threat data using APIs (VirusTotal, GreyNoise, etc.)
-  Reduce mean time to detect (MTTD) and mean time to respond (MTTR)
-  Support SOAR playbooks and workflows for automated IR

<br> <br/>

## 2. Use Cases

| Use Case                | Description                                                       |
|-------------------------|-------------------------------------------------------------------|
| **Malware Detection**   | Scan and isolate infected files using YARA or antivirus CLI tools |
| **Log Analysis**        | Parse syslogs, Windows logs to detect suspicious activity         |
| **Firewall Automation** | Block malicious IPs/domains via iptables or Windows Firewall      |
| **IOC Enrichment**      | Use threat intel APIs to contextualize IOCs                       |
| **Phishing Detection**  | Extract and analyze suspicious links/attachments in emails        |
| **User Monitoring**     | Track anomalous behavior from endpoint or AD logs                 |
| **SIEM Pre-processing** | Format, tag, and enrich logs before forwarding to SIEM            |

<br> <br/>

## 3. Architecture Overview

### Components:
- **Input Sources:** Syslogs, endpoint logs, threat intel feeds, email headers
- **Processing:** Python, PowerShell, Bash scripts; API queries; regex parsing
- **Output:** Alerts, blocked IPs, enriched logs, JSON reports, firewall rules
- **Toolchain:** CRON, Task Scheduler, Docker, SOAR, ELK Stack, VirusTotal, GreyNoise

<br> <br/>

## 4. Scripting Languages & Environments

| Language     | Use Case Highlights                                           |
|--------------|---------------------------------------------------------------|
| **Python**   | REST APIs, log parsing, enrichment, response automation       |
| **PowerShell** | Windows event logs, registry keys, WMI queries               |
| **Bash**     | File scanning, automation, Linux firewall interaction         |
| **Node.js**  | Webhook handling, microservices integration                   |

<br> <br/>

## 5. Example Scripts

### 5.1 Python: IP Reputation Check & Block

```python
import requests, subprocess

def check_ip(ip):
    response = requests.get(f"https://ip-api.com/json/{ip}")
    if response.ok:
        data = response.json()
        return data['country'], data['isp']
    return None, None

def block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

if __name__ == "__main__":
    ip = "45.77.123.21"
    country, isp = check_ip(ip)
    print(f"Blocking IP from {country}, ISP: {isp}")
    block_ip(ip)
```

<br> <br/>

### 5.2 PowerShell: Brute-Force Logon Detection

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
foreach ($event in $events) {
    $ip = ($event.Message -split "`n") -match "Source Network Address" |
          ForEach-Object { ($_ -split ":")[1].Trim() }
    Write-Output "Failed login from IP: $ip"
}
```

<br> <br/>

###  5.3 Bash: YARA File Scanner

```bash
#!/bin/bash

YARA_RULES="/opt/yara/rules.yar"
TARGET_DIR="/var/www/html/uploads"

for file in $(find $TARGET_DIR -type f); do
    yara $YARA_RULES $file
    if [ $? -eq 0 ]; then
        echo "[!] Malware found in $file"
        mv "$file" /quarantine/
    fi
done
```

<br> <br/>

### 5.4 Python: IOC Enrichment with VirusTotal

```python
import requests

API_KEY = "your_api_key"
IOC = "8.8.8.8"
url = f"https://www.virustotal.com/api/v3/ip_addresses/{IOC}"
headers = {"x-apikey": API_KEY}

response = requests.get(url, headers=headers)
if response.ok:
    data = response.json()
    print(f"{IOC} malicious score: {data['data']['attributes']['last_analysis_stats']['malicious']}")
```

<br> <br/>

## 6. Integration Targets


| **Platform**       | **Integration Method**                             |
|--------------------|----------------------------------------------------|
| **Splunk**         | HTTP Event Collector, Python SDK                   |
| **Cortex XSOAR**   | Python automation scripts                          |
| **CrowdStrike**    | Falcon API (IOC blocking)                          |
| **AlienVault OTX** | Threat intelligence API                            |
| **GreyNoise**      | IP context enrichment, noise filtering             |
| **Firewalls**      | `iptables`, `firewalld`, Windows PowerShell rules  |


<br> <br/>

## 7. Best Practices

+ Use sandbox environments before production deployment
+ Maintain verbose logs for every action
+ Implement error handling and rollback mechanisms
+ Design scripts to be modular and reusable
+ Document configs, schedules, and dependencies
+ Include manual override and kill switches

<br> <br/>

## 8. Deployment & Scheduling

### Windows Task Scheduler
   + Run eventlog_scan.ps1 every 30 minutes
   + Use .ps1 execution policy configuration

### Docker Deployment
Containerize scripts using lightweight base images for portability and CI/CD.

<br> <br/>

## 9. Logging & Monitoring
   + Log all activity to /var/log/threat_automation/
   + Ship logs to ELK Stack, Graylog, or Fluentd
   + Integrate with Prometheus + Grafana for uptime and status monitoring

<br> <br/>

## 10. Future Enhancements

+ Integrate anomaly detection via ML models
+ Integrate with email security gateways
+ Add honeypot trigger responses
+ Support blockchain-based IOC verification
+ Enable AWS Lambda/Cloud Functions compatibility


