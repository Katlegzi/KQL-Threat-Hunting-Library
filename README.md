KQL Threat Hunting & Incident Detection Library

# Overview
This repository contains production-ready Kusto Query Language (KQL) detection rules and threat hunting queries designed for **Microsoft Sentinel**, **Defender for Cloud**, and **Azure Data Explorer (ADX)**. 

Each query focuses on noise reduction, actionable alert outputs, and explicit mapping to the **MITRE ATT&CK Framework**.

---

# Detection Rule 01: High-Volume Brute-Force & Password Spray Detection

# Objective
Identifies user accounts experiencing excessive failed authentication attempts within a short timeframe, filtering out accidental password typos to isolate active password spraying or brute-force attacks.

# MITRE ATT&CK Mapping
* **Tactics:** Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/))
* **Techniques:** Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/)), Password Spraying ([T1110.003](https://attack.mitre.org/techniques/T1110/003/))

# KQL Query Logic

```kql
// Source Dataset: Azure Data Explorer / Microsoft Sentinel SecurityLogs

---
```
Detection Rule 02: Suspicious Executable & Script Creation in User Directories

# Objective
Detects executable binaries (`.exe`, `.ps1`, `.bat`) created outside standard system directories (`System32`, `Program Files`), isolating potential malware droppers, masqueraded binaries, or unauthorized user downloads.

# MITRE ATT&CK Mapping
* **Tactics:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)), Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
* **Techniques:** Masquerading ([T1036](https://attack.mitre.org/techniques/T1036/)), User Execution ([T1204](https://attack.mitre.org/techniques/T1204/))

# KQL Query Logic

```kql
// Source Dataset: Azure Data Explorer / Microsoft Sentinel SecurityLogs
database("SecurityLogs").FileCreationEvents
| where (filename endswith ".exe" or filename endswith ".ps1" or filename endswith ".bat")
  and path !has "System32" and path !has "Program Files"
| extend Severity = "Medium-High", AlertTitle = "Suspicious Executable Created in User Directory"
| project Hostname = hostname, FileName = filename, FilePath = path, SHA256 = sha256, Severity, AlertTitle
| sort by Hostname asc
database("SecurityLogs").AuthenticationEvents
| summarize FailedCount = count() by TargetUser = username, EventResult = result
| where EventResult == "Failed Login" and FailedCount > 15
| extend Severity = "High", AttackType = "Brute Force / Password Spray"
| project TargetUser, FailedCount, Severity, AttackType, EventResult
| sort by FailedCount desc
