# SIEM Threat Detection Project — Splunk Cloud

## Overview
This project demonstrates **SIEM threat detection** using **Splunk Cloud** and **Windows Event Logs**.  
Objective: Detect and respond to brute-force login attempts (Event ID 4625) through log ingestion and detection logic.

---

## Project Objectives
- Configure **Splunk Cloud** and **Universal Forwarder** for Windows log ingestion.  
- Simulate brute-force login attempts using PowerShell.  
- Detect repeated failed login attempts (EventCode 4625).  
- Generate alerts and visualize failed logons through dashboards.  
- Map detection logic to **MITRE ATT&CK T1110 (Brute Force)**.

---

## Environment Setup
- **SIEM:** Splunk Cloud  
- **Forwarder:** Splunk Universal Forwarder (Windows)  
- **Log Source:** Windows Event Log (Security)  
- **Event Codes:** 4624 (Success Logon), 4625 (Failed Logon)  
- **Host:** Odus (Local Windows Machine)

### Steps
1. Installed and configured the **Splunk Universal Forwarder**.  
2. Added Security Event Logs to monitored inputs.  
3. Confirmed data ingestion using:
   ```spl
   index=* host=Odus EventCode=4625

## Attack Simulation

Simulated brute-force attempts by repeatedly providing incorrect credentials:
net user testuser Password123! /add
for ($i=0; $i -lt 10; $i++) 
{
  net use \\localhost\IPC$wrongpass /user:testuser > $null 2>&1
  Start-Sleep -Milliseconds 500
}

These repeated login failures generated EventCode 4625 in Windows Security logs, forwarded to Splunk Cloud in real-time.

## Detection Logic (SPL Query)

The detection was based on identifying multiple failed logons from the same user within a short timeframe:
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count AS failed_attempts BY Account_Name, Source_Network_Address
| where failed_attempts >= 5

This query triggers when 5 or more failed login attempts occur, signaling potential brute-force behavior.

## Verification

To view raw failed logon events:
index=* host=Odus EventCode=4625
| table _time, Account_Name, Source_Network_Address, Failure_Reason
| sort - _time

## Alert Configuration

Trigger Condition: Failed logins ≥ 5 within 10 minutes
Action: Email notification to SOC team
Severity: Medium
Throttle: 10 minutes
Index Used: windows_logs

## Results

✅ Successfully detected simulated brute-force attacks
✅ Dashboard visualized failed attempts by user
✅ Detection mapped to MITRE ATT&CK T1110
✅ Demonstrated full SOC detection and response cycle


## Tools Used

Splunk Cloud
Splunk Universal Forwarder
Windows 10 Event Logs

PowerShell
