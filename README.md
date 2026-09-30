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
database("SecurityLogs").AuthenticationEvents
| summarize FailedCount = count() by TargetUser = username, EventResult = result
| where EventResult == "Failed Login" and FailedCount > 15
| extend Severity = "High", AttackType = "Brute Force / Password Spray"
| project TargetUser, FailedCount, Severity, AttackType, EventResult
| sort by FailedCount desc
