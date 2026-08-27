# Investigation Evidence

This folder contains screenshots captured from a Splunk Enterprise lab
using the simulated security-event dataset included in this repository.

The evidence demonstrates the investigation workflow from authentication
analysis through privilege activity, process execution, network activity,
persistence, PowerShell analysis, and full incident correlation.

> **Environment:** Simulated SOC Lab  
> **Platform:** Splunk Enterprise  
> **Data Source:** `simulated_security_events.csv`

---

## 1. Authentication Analysis

Five failed authentication attempts were followed by a successful
interactive logon for the `jsmith` account on endpoint `WKSTN-104`.

This sequence triggered further investigation because the successful
authentication occurred shortly after repeated failures.

![Authentication Analysis](01-authentication-analysis.png)

---

## 2. Privilege and Process Analysis

Following the successful authentication, the investigation identified
special privileges assigned to the session, followed by execution of
`powershell.exe` and `rundll32.exe`.

These processes are legitimate Windows components, but their timing
within the broader event sequence increased investigative concern.

![Privilege and Process Analysis](02-privilege-process-analysis.png)

---

## 3. Network and Persistence Analysis

The endpoint established outbound connections to the simulated network
artifact `203.0.113.50:443`.

A scheduled task named `WindowsUpdateCheck` was also created, with later
activity occurring under the `SYSTEM` context.

The combination of network communication and scheduled-task activity
raised concern for potential persistence within the simulated scenario.

![Network and Persistence Analysis](03-network-persistence-analysis.png)

---

## 4. PowerShell Analysis

Multiple PowerShell execution events were identified during the
investigation.

PowerShell script-block telemetry later recorded an `EncodedCommand`
artifact, increasing the priority of the PowerShell activity for further
analysis.

The dataset does not contain the decoded command, so the investigation
does not claim to identify the actual PowerShell payload.

![PowerShell Analysis](04-powershell-analysis.png)

---

## 5. Complete Incident Timeline

The full Splunk timeline correlates the major security events associated
with the investigation:

- Repeated authentication failures
- Successful authentication
- Privilege assignment
- PowerShell execution
- `rundll32.exe` execution
- Outbound network communication
- Scheduled-task creation
- Continued activity under `SYSTEM`
- Encoded PowerShell telemetry

This correlation supported the final True Positive classification within
the simulated scenario.

![Complete Incident Timeline](05-incident-timeline.png)

---

## Evidence Summary

The screenshots demonstrate practical use of Splunk for:

- SIEM event investigation
- SPL searching
- Authentication analysis
- Log correlation
- Privilege-event investigation
- Process analysis
- Network-event analysis
- Persistence investigation
- PowerShell analysis
- Incident timeline reconstruction

---

## Disclaimer

All events and screenshots in this project use simulated lab data.

No employer, customer, production-system, or confidential security
information is included.
