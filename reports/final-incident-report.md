# Final SOC Incident Report

## Incident Summary

**Incident Title:** Suspicious Authentication and Post-Authentication Activity

**Incident Classification:** True Positive — Simulated Scenario

**Severity:** High

**Incident Category:** Suspected Account Compromise / Unauthorized Post-Authentication Activity

**Affected User:** `jsmith`

**Affected Endpoint:** `WKSTN-104`

**Investigated Source IP:** `10.10.20.15`

**Investigated Network Destination:** `203.0.113.50:443`

**Environment:** Simulated SOC Lab

---

## 1. Executive Summary

A Security Operations Center investigation was initiated after multiple failed authentication attempts involving the `jsmith` account were followed by a successful login.

Initial authentication analysis identified five failed login attempts followed shortly by a successful authentication on endpoint `WKSTN-104`.

Follow-on analysis identified additional activity involving:

* Special privilege assignment
* PowerShell execution
* `rundll32.exe` execution
* Outbound network communication
* Scheduled-task creation
* Continued activity under the SYSTEM context
* Encoded PowerShell activity

The correlation of authentication, privilege, execution, network, and persistence-related events resulted in the alert being classified as a **True Positive within the simulated scenario**.

The incident was assigned **High severity** and escalated for simulated incident-response actions.

---

## 2. Detection

The investigation began with repeated Windows authentication failures associated with the `jsmith` account.

Five Event ID `4625` authentication failures occurred within approximately 30 seconds.

These failures were followed by Event ID `4624`, indicating a successful authentication.

The proximity between the failed attempts and successful authentication warranted further investigation.

---

## 3. Initial Triage

Initial triage focused on:

* User account
* Source IP
* Endpoint
* Authentication result
* Event timestamps
* Follow-on security activity

### Initial Findings

**User:** `jsmith`

**Host:** `WKSTN-104`

**Source IP:** `10.10.20.15`

**Initial Classification:** Suspicious — Further Investigation Required

At this stage, authentication activity alone was not sufficient to establish compromise.

---

## 4. Investigation Timeline

| Time     | Event ID | Activity                                    | Assessment                       |
| -------- | -------: | ------------------------------------------- | -------------------------------- |
| 09:01:12 |     4625 | Failed authentication                       | Authentication anomaly           |
| 09:01:18 |     4625 | Failed authentication                       | Repeated failure                 |
| 09:01:25 |     4625 | Failed authentication                       | Pattern developing               |
| 09:01:31 |     4625 | Failed authentication                       | Continued failures               |
| 09:01:42 |     4625 | Failed authentication                       | Fifth observed failure           |
| 09:02:03 |     4624 | Successful authentication                   | Investigation required           |
| 09:02:15 |     4672 | Special privileges assigned                 | Elevated concern                 |
| 09:02:44 |     4688 | `powershell.exe` created                    | Suspicious in context            |
| 09:03:02 |     4688 | `rundll32.exe` created                      | Additional execution             |
| 09:03:21 |     5156 | Outbound connection to `203.0.113.50:443`   | Network artifact                 |
| 09:04:01 |     4698 | `WindowsUpdateCheck` scheduled task created | Potential persistence            |
| 09:04:25 |     5156 | Additional outbound connection              | Continued communication          |
| 09:05:10 |     4688 | PowerShell executed                         | Continued activity               |
| 09:09:10 |     4634 | User logoff                                 | Interactive session terminated   |
| 09:12:04 |     4698 | Scheduled-task activity under SYSTEM        | Persistence concern              |
| 09:13:11 |     5156 | SYSTEM outbound communication               | Continued activity               |
| 09:14:20 |     4688 | PowerShell executed                         | Continued execution              |
| 09:15:02 |     4104 | PowerShell `EncodedCommand` logged          | High-interest execution artifact |
| 09:16:30 |     5156 | Additional outbound connection              | Continued communication          |

---

## 5. Authentication Analysis

The authentication sequence consisted of repeated failed login attempts followed shortly by a successful authentication.

The sequence was treated as suspicious because:

1. Multiple failures occurred against the same account.
2. The failures occurred within a short period.
3. A successful authentication followed shortly afterward.
4. Additional privileged and endpoint activity occurred following authentication.

Authentication activity alone did not establish compromise, so follow-on endpoint and network telemetry was analyzed.

---

## 6. Privilege and Process Analysis

Shortly after the successful authentication, Event ID `4672` recorded special privileges associated with the session.

The investigation subsequently identified execution of:

* `powershell.exe`
* `rundll32.exe`
* `cmd.exe`

These Windows binaries have legitimate administrative uses and were not classified as malicious solely because they executed.

Their significance increased because they occurred immediately following suspicious authentication and privilege activity.

---

## 7. PowerShell Analysis

PowerShell execution occurred multiple times during the investigation.

Later telemetry included a PowerShell script-block event containing:

`EncodedCommand`

Encoded PowerShell activity was considered a high-interest investigation artifact because encoded commands can obscure executed content.

However, the available simulated dataset does not contain the decoded PowerShell command.

Additional script-block and command-line telemetry would be required for complete analysis.

---

## 8. Network Analysis

Outbound network communication was observed between `WKSTN-104` and:

`203.0.113.50:443`

The connection occurred following suspicious process activity and was observed multiple times during the incident timeline.

The destination was treated as an investigation artifact.

The available dataset does not contain sufficient network telemetry to establish command-and-control behavior or determine the application-layer activity.

Additional DNS, proxy, firewall, packet-capture, and EDR telemetry would be required in a production investigation.

---

## 9. Persistence Analysis

Event ID `4698` recorded creation of a scheduled task named:

`WindowsUpdateCheck`

The task was created shortly after PowerShell execution and outbound network activity.

Later telemetry showed scheduled-task and network activity occurring under the `SYSTEM` context after the original user session had ended.

This increased concern that the task represented a persistence mechanism within the simulated incident.

The scheduled task should be preserved and examined before removal during a real incident.

---

## 10. Identified Investigation Artifacts

| Artifact             | Type                | Assessment                       |
| -------------------- | ------------------- | -------------------------------- |
| `jsmith`             | User Account        | Affected account                 |
| `WKSTN-104`          | Endpoint            | Affected endpoint                |
| `10.10.20.15`        | Internal IP         | Investigation artifact           |
| `203.0.113.50:443`   | Network Destination | Requires validation              |
| `powershell.exe`     | Process             | Suspicious in context            |
| `rundll32.exe`       | Process             | Suspicious in context            |
| `cmd.exe`            | Process             | Supporting execution artifact    |
| `WindowsUpdateCheck` | Scheduled Task      | Potential persistence artifact   |
| `EncodedCommand`     | PowerShell Artifact | High-interest execution artifact |
| `SeDebugPrivilege`   | Privilege           | Privileged-session artifact      |
| `SeBackupPrivilege`  | Privilege           | Privileged-session artifact      |

---

## 11. Scope Assessment

Based on the available dataset, the observed activity was primarily associated with:

**Account:** `jsmith`

**Endpoint:** `WKSTN-104`

The dataset does not establish whether additional endpoints or user accounts were affected.

In a production investigation, enterprise-wide searches should be conducted for:

* Similar authentication patterns
* Same account across additional endpoints
* Same scheduled-task name
* Similar PowerShell activity
* Same network destination
* Related process execution
* Related EDR detections

The incident should not be considered fully scoped until broader telemetry is reviewed.

---

## 12. MITRE ATT&CK Mapping

### Supported Techniques

**T1059.001 — Command and Scripting Interpreter: PowerShell**

Evidence:

* PowerShell process execution
* PowerShell script-block telemetry
* EncodedCommand activity

**T1053.005 — Scheduled Task/Job: Scheduled Task**

Evidence:

* Creation of `WindowsUpdateCheck`
* Later task-associated activity under SYSTEM

### Contextual / Potential Techniques

**T1110 — Brute Force**

Repeated failed authentications followed by successful authentication are consistent with behavior requiring investigation for password guessing or brute-force activity.

The dataset does not independently prove brute force.

**T1218.011 — System Binary Proxy Execution: Rundll32**

`rundll32.exe` execution was observed.

Command-line arguments and DLL execution details were not available, so this mapping requires additional validation.

---

## 13. Final Classification

### Alert Classification

**True Positive — Simulated Scenario**

### Severity

**High**

### Incident Type

**Suspected Account Compromise with Post-Authentication Activity**

### Rationale

The determination was based on correlation of:

1. Repeated authentication failures
2. Successful authentication
3. Privileged-session activity
4. PowerShell execution
5. rundll32 execution
6. Outbound network communication
7. Scheduled-task creation
8. Continued activity under SYSTEM
9. Encoded PowerShell telemetry

No single event independently established compromise.

The correlated sequence provided sufficient evidence within the simulated scenario to escalate the event as a security incident.

---

## 14. Containment Recommendations

### Account

* Temporarily restrict or disable the affected account according to policy
* Revoke active sessions where supported
* Review permissions and group memberships
* Validate the activity with the account owner
* Reset credentials if unauthorized access is confirmed
* Review MFA and authentication controls

### Endpoint

* Isolate `WKSTN-104` using approved EDR controls where appropriate
* Preserve relevant evidence
* Prevent continued execution of confirmed unauthorized processes
* Restrict unnecessary network communication

### Network

* Validate the investigated destination
* Search enterprise telemetry for additional connections
* Block confirmed unauthorized network indicators using approved controls

---

## 15. Eradication Recommendations

After containment and evidence preservation:

* Remove confirmed unauthorized scheduled tasks
* Remove unauthorized scripts or files
* Terminate confirmed malicious processes
* Remove persistence mechanisms
* Review access-control changes
* Patch relevant vulnerabilities if discovered
* Confirm unauthorized network activity has stopped

---

## 16. Recovery Recommendations

Before returning the system to normal operation:

* Reset credentials where required
* Restore appropriate account permissions
* Re-enable accounts only after validation
* Verify endpoint security controls
* Confirm system integrity
* Reconnect the endpoint after security review
* Monitor closely for recurrence

---

## 17. Post-Incident Monitoring

Monitor for:

* Repeated authentication failures
* Unusual successful authentication
* Privileged logons
* Suspicious PowerShell activity
* rundll32 execution
* Scheduled-task creation
* Similar outbound network communication
* Reuse of identified artifacts across other systems

---

## 18. Lessons Learned

The investigation demonstrates the importance of correlating multiple telemetry sources rather than evaluating security events individually.

Key lessons include:

* Failed authentications should be correlated with subsequent successful logins.
* Authentication events should be correlated with endpoint activity.
* Legitimate Windows tools must be evaluated in context.
* Persistence activity may continue after the interactive user session ends.
* Network events should be correlated with process and endpoint telemetry.
* SIEM investigations require evidence-based classification.
* Analysts should distinguish suspicious artifacts from confirmed malicious indicators.
* Scope determination should extend beyond the initially affected endpoint.

---

## 19. Recommended Security Improvements

* Improve correlation of failed and successful authentication events
* Monitor privileged logon activity
* Strengthen PowerShell visibility and script-block logging
* Monitor scheduled-task creation
* Improve endpoint/network telemetry correlation
* Maintain least-privilege access
* Review MFA coverage
* Tune SIEM detection rules based on investigation findings
* Maintain tested incident-response playbooks
* Conduct post-incident reviews to improve detection and response

---

## 20. Incident Status

| Phase                | Status                  |
| -------------------- | ----------------------- |
| Detection            | Completed               |
| Triage               | Completed               |
| Investigation        | Completed               |
| Correlation          | Completed               |
| Classification       | Completed               |
| MITRE ATT&CK Mapping | Completed               |
| Containment          | Recommended / Simulated |
| Eradication          | Recommended / Simulated |
| Recovery             | Recommended / Simulated |
| Lessons Learned      | Completed               |

---

## Conclusion

The simulated SOC investigation demonstrated an end-to-end security-analysis workflow beginning with suspicious authentication activity and progressing through log analysis, event correlation, privilege analysis, endpoint investigation, network analysis, persistence identification, artifact analysis, incident classification, and response planning.

The investigation was classified as a **True Positive within the simulated scenario** because multiple related security events formed a coherent pattern of suspicious post-authentication behavior.

The project demonstrates practical SOC competencies including SIEM investigation, log correlation, alert classification, IOC/artifact analysis, incident-response decision-making, MITRE ATT&CK mapping, and professional security documentation.

---

## Portfolio Disclaimer

This report documents a controlled cybersecurity portfolio exercise using simulated security-event data.

No employer, customer, production-system, or confidential security information is included.

The containment, eradication, and recovery actions described in this report are recommended actions for the simulated scenario and were not represented as actions performed against a real production environment.
