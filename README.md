# SOC SIEM Incident Investigation

**Security Operations | Splunk Enterprise | SIEM | Incident Response | MITRE ATT&CK**

This project demonstrates an end-to-end **Security Operations Center (SOC) investigation** using Splunk Enterprise and a simulated Windows security-event dataset.

The investigation follows suspicious authentication activity from initial triage through log analysis, event correlation, privilege and process investigation, network activity, persistence analysis, PowerShell investigation, incident classification, MITRE ATT&CK mapping, and incident-response recommendations.

### Project Overview

| Category | Details |
|---|---|
| **Project Type** | Hands-on Cybersecurity Portfolio Project |
| **Environment** | Simulated SOC Lab |
| **Primary SIEM** | Splunk Enterprise |
| **Classification** | True Positive — Simulated Scenario |
| **Severity** | High |

---

## Project Objective

This project demonstrates practical SOC analyst capabilities in:

* SIEM monitoring and investigation
* Splunk SPL searching
* Security log analysis
* Alert triage
* Event correlation
* True/false-positive analysis
* Authentication investigation
* Privilege and process analysis
* IOC and artifact analysis
* Network-event investigation
* Persistence detection
* PowerShell analysis
* Incident timeline reconstruction
* MITRE ATT&CK mapping
* Incident-response planning
* Security documentation

---

## Incident Scenario

The investigation begins with multiple failed authentication attempts involving:

**User:** `jsmith`
**Endpoint:** `WKSTN-104`
**Source IP:** `10.10.20.15`

Five failed authentication attempts were followed shortly by a successful interactive logon.

Follow-on investigation identified:

* Special privilege assignment
* PowerShell execution
* `rundll32.exe` execution
* Outbound network communication
* Scheduled-task creation
* Continued activity under the `SYSTEM` context
* Encoded PowerShell activity

The events were correlated to determine whether the original authentication alert represented legitimate activity or a security incident.

---

## Investigation Workflow

```text
Security Alert
      ↓
Initial Triage
      ↓
Authentication Analysis
      ↓
Log Correlation
      ↓
Privilege & Process Analysis
      ↓
Network Analysis
      ↓
Persistence Analysis
      ↓
PowerShell Analysis
      ↓
IOC / Artifact Analysis
      ↓
Scope Determination
      ↓
Incident Classification
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Response
```

---

## 1. Authentication Analysis

Splunk analysis identified five Event ID `4625` failed authentication attempts followed by Event ID `4624`, representing a successful interactive logon.

This pattern was classified as suspicious and required further investigation.

**Evidence:**
[View Authentication Investigation](findings/authentication-finding.md)
[View Splunk Authentication Screenshot](evidence/01-authentication-analysis.png.png)

---

## 2. Privilege & Process Analysis

Following successful authentication, the investigation identified:

* Event ID `4672` — Special privileges assigned
* Event ID `4688` — `powershell.exe`
* Event ID `4688` — `rundll32.exe`

These events were not treated as malicious independently. Their significance came from their timing and correlation with the suspicious authentication activity.

**Evidence:**
[View Privilege & Process Investigation](findings/privilege-process-finding.md)
[View Splunk Privilege & Process Screenshot](evidence/02-privilege-process-analysis.png.png)

---

## 3. Network & Persistence Analysis

The endpoint established outbound connections to the simulated network artifact:

`203.0.113.50:443`

A scheduled task named:

`WindowsUpdateCheck`

was also created.

Later activity associated with the scheduled task and network communication occurred under the `SYSTEM` context, increasing concern for persistence.

**Evidence:**
[View Network & Persistence Investigation](findings/network-persistence-finding.md)
[View Splunk Network & Persistence Screenshot](evidence/03-network-persistence-analysis.png.png)

---

## 4. PowerShell Analysis

Multiple PowerShell execution events were identified during the investigation.

Later PowerShell script-block telemetry recorded:

`EncodedCommand`

Because the simulated dataset does not contain the decoded command, this artifact was treated as high-interest suspicious activity without claiming knowledge of the underlying payload.

**Evidence:**
[View Splunk PowerShell Screenshot](evidence/04-powershell-analysis.png.png)

---

## Complete Incident Timeline

The investigation correlated the following sequence:

```text
Failed Logons
     ↓
Successful Logon
     ↓
Special Privileges
     ↓
PowerShell
     ↓
rundll32.exe
     ↓
Outbound Connection
     ↓
Scheduled Task
     ↓
SYSTEM Activity
     ↓
Encoded PowerShell
```

[View Incident Timeline](documentation/incident-timeline.md)
[View Full Splunk Timeline](evidence/05-incident-timeline.png.png)

---

## Key Investigation Artifacts

| Artifact             | Type                | Assessment                     |
| -------------------- | ------------------- | ------------------------------ |
| `jsmith`             | User Account        | Affected account               |
| `WKSTN-104`          | Endpoint            | Affected endpoint              |
| `10.10.20.15`        | Internal IP         | Investigation artifact         |
| `203.0.113.50:443`   | Network Destination | Requires validation            |
| `powershell.exe`     | Process             | Suspicious in context          |
| `rundll32.exe`       | Process             | Suspicious in context          |
| `WindowsUpdateCheck` | Scheduled Task      | Potential persistence artifact |
| `EncodedCommand`     | PowerShell Artifact | High-interest artifact         |
| `SeDebugPrivilege`   | Privilege           | Privileged-session artifact    |
| `SeBackupPrivilege`  | Privilege           | Privileged-session artifact    |

[View IOC & Artifact Analysis](findings/ioc-analysis.md)

---

## Final Incident Classification

**Classification:** True Positive — Simulated Scenario
**Severity:** High
**Incident Type:** Suspected Account Compromise with Post-Authentication Activity

The classification was based on the correlation of multiple events rather than a single alert.

Evidence included:

1. Repeated failed authentications
2. Successful authentication
3. Special privilege assignment
4. PowerShell execution
5. `rundll32.exe` execution
6. Network communication
7. Scheduled-task creation
8. Continued SYSTEM activity
9. Encoded PowerShell telemetry

[View Final Classification](findings/final-classification.md)

---

## MITRE ATT&CK Mapping

| Observed Behavior      | ATT&CK Technique                                              | ID          |
| ---------------------- | ------------------------------------------------------------- | ----------- |
| PowerShell execution   | Command and Scripting Interpreter: PowerShell                 | `T1059.001` |
| Scheduled task         | Scheduled Task/Job: Scheduled Task                            | `T1053.005` |
| Authentication pattern | Brute Force — contextual mapping                              | `T1110`     |
| rundll32 execution     | System Binary Proxy Execution: Rundll32 — requires validation | `T1218.011` |

The investigation intentionally avoids assigning ATT&CK techniques where the available telemetry does not provide sufficient evidence.

[View MITRE ATT&CK Mapping](documentation/mitre-attack-mapping.md)

---

## Incident Response

The simulated response plan addresses:

### Containment

* Protect or restrict the affected account
* Revoke active sessions where appropriate
* Isolate the affected endpoint if required
* Restrict confirmed unauthorized network activity
* Preserve investigation evidence

### Eradication

* Investigate and remove unauthorized persistence
* Remove confirmed unauthorized artifacts
* Review account permissions
* Address identified security weaknesses

### Recovery

* Reset affected credentials when required
* Validate endpoint security
* Restore approved access
* Monitor for recurrence

[View Incident Response Plan](documentation/incident-response.md)

---

## Splunk Investigation Evidence

The simulated security dataset was ingested into **Splunk Enterprise**, where SPL searches were used to investigate and correlate the events.

[View Complete Splunk Evidence](evidence/)

Evidence includes:

1. Authentication Analysis
2. Privilege & Process Analysis
3. Network & Persistence Analysis
4. PowerShell Analysis
5. Complete Incident Timeline

---

## Investigation Queries

### Splunk SPL

* `queries/authentication-analysis.spl`
* `queries/privilege-analysis.spl`
* `queries/network-persistence-analysis.spl`

### Microsoft Sentinel / KQL Examples

* `queries/authentication-analysis.kql`
* `queries/privilege-analysis.kql`
* `queries/network-powershell-analysis.kql`

> The KQL files demonstrate equivalent Microsoft Sentinel investigation methodology using simulated project data. They are not presented as production Sentinel query execution.

---

## Final Incident Report

The final SOC incident report consolidates:

* Detection
* Triage
* Authentication analysis
* Privilege and process analysis
* Network analysis
* Persistence analysis
* PowerShell analysis
* Incident timeline
* IOC/artifact analysis
* Scope
* Classification
* MITRE ATT&CK mapping
* Incident-response recommendations
* Lessons learned

[View Final SOC Incident Report](reports/final-incident-report.md)

---

## Tools & Technologies

**SIEM & Querying**

* Splunk Enterprise
* SPL
* Microsoft Sentinel / KQL methodology

**Security Analysis**

* Windows Security Events
* Authentication Logs
* Process Telemetry
* PowerShell Logs
* Network Events
* Persistence Events

**Frameworks & Methodology**

* MITRE ATT&CK
* Incident Response
* SOC Alert Triage
* Event Correlation

---

## Skills Demonstrated

* SOC Operations
* SIEM Monitoring
* Splunk
* SPL
* Log Analysis
* Alert Triage
* Event Correlation
* Authentication Analysis
* Incident Investigation
* True Positive Classification
* IOC / Artifact Analysis
* Windows Security Monitoring
* PowerShell Investigation
* Network Analysis
* Persistence Analysis
* MITRE ATT&CK Mapping
* Incident Response
* Security Documentation

---

## Project Evidence

All screenshots were captured from a Splunk Enterprise lab using the simulated dataset included in this repository.

No employer, customer, production-system, or confidential security information is included.

Containment, eradication, and recovery activities are documented as recommended actions for the simulated scenario and are not represented as actions performed against a production environment.

