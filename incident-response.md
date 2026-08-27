# Incident Response Plan

## Incident Overview

The simulated investigation identified a suspicious sequence involving
the `jsmith` account and endpoint `WKSTN-104`.

The activity included repeated authentication failures followed by a
successful authentication, privilege assignment, PowerShell and
rundll32 execution, outbound network communication, scheduled-task
creation, and additional PowerShell activity.

Based on the correlated evidence in this simulated scenario, the alert
was classified as a True Positive requiring incident-response actions.

---

## Incident Response Objectives

The response objectives are to:

1. Contain potentially unauthorized activity
2. Protect the affected account
3. Prevent additional network communication
4. Preserve evidence for further investigation
5. Remove unauthorized persistence if confirmed
6. Restore the affected system securely
7. Monitor for recurrence or related activity

---

# 1. Containment

## Account Containment

The affected account is:

`jsmith`

Recommended actions:

- Temporarily disable or restrict the account according to organizational policy
- Revoke active sessions where supported
- Review recent authentication activity
- Review account permissions and group memberships
- Determine whether authentication originated from an authorized user
- Require credential reset if unauthorized access is confirmed
- Review MFA status and authentication controls

## Endpoint Containment

Affected endpoint:

`WKSTN-104`

Recommended actions:

- Isolate the endpoint through the organization's EDR platform if appropriate
- Restrict unnecessary network communication
- Preserve volatile and relevant forensic evidence where required
- Prevent continued execution of confirmed unauthorized activity
- Maintain sufficient access for approved investigation procedures

## Network Containment

Investigated network artifact:

`203.0.113.50:443`

Recommended actions:

- Validate the destination against approved network activity
- Search network telemetry for other systems communicating with the same destination
- If confirmed unauthorized within the simulated scenario, block the relevant indicator using approved security controls
- Continue monitoring for attempted communication

> Note: `203.0.113.50` is used as a simulated/documentation address in this portfolio project and is not presented as a real-world threat-intelligence-confirmed malicious IP.

---

# 2. Evidence Preservation

Before destructive remediation, relevant evidence should be preserved
according to organizational incident-response and forensic procedures.

Potential evidence includes:

- Authentication logs
- Windows Security events
- PowerShell logs
- Process execution telemetry
- EDR telemetry
- Scheduled-task information
- Network connection records
- Relevant SIEM alerts
- Account activity
- Investigation notes and timestamps

Evidence preservation supports:

- Root-cause analysis
- Scope determination
- Incident documentation
- Lessons learned
- Potential compliance or legal requirements

---

# 3. Eradication

After containment and evidence preservation, investigate and remove
confirmed unauthorized artifacts.

Recommended actions include:

- Remove unauthorized scheduled tasks
- Terminate confirmed malicious or unauthorized processes
- Remove unauthorized scripts or files
- Remove unauthorized persistence mechanisms
- Review account permissions for unauthorized changes
- Patch exploitable vulnerabilities if identified
- Remove or quarantine confirmed malicious artifacts through approved endpoint controls
- Verify that unauthorized network communication has stopped

The scheduled task:

`WindowsUpdateCheck`

should be investigated before removal to determine its origin, execution
history, and relationship to the suspicious activity.

---

# 4. Recovery

After eradication, return the affected account and endpoint to normal
operation only after security validation.

Recommended recovery actions:

- Reset affected credentials where required
- Restore appropriate account permissions
- Re-enable the account only after validation
- Reconnect the endpoint to the network after security review
- Confirm required security controls are operational
- Update endpoint protection and security tooling
- Perform additional vulnerability or configuration assessment if appropriate
- Validate normal system operation

---

# 5. Post-Recovery Monitoring

Recovery does not immediately end the investigation.

Increase monitoring for:

- Additional failed authentication attempts
- Unusual successful logins
- Privilege-assignment events
- PowerShell execution
- rundll32 activity
- Scheduled-task creation
- Repeated network connections to investigated destinations
- Similar behavior on other endpoints
- Additional activity involving the affected account

---

# 6. Enterprise Scope Validation

The available simulated dataset primarily identifies activity involving:

- Account: `jsmith`
- Endpoint: `WKSTN-104`

A real-world SOC investigation should search the broader environment for
related activity before declaring the incident fully contained.

Recommended searches include:

- Same account on additional endpoints
- Same network artifact across additional hosts
- Similar scheduled-task names
- Similar PowerShell activity
- Related process execution
- Similar authentication patterns
- Related EDR detections

---

# 7. Lessons Learned

Following recovery, conduct a post-incident review.

Questions should include:

1. How was the activity initially detected?
2. Were the existing detection rules effective?
3. Could the suspicious authentication sequence have been identified earlier?
4. Were account protections sufficient?
5. Did endpoint monitoring provide enough visibility?
6. Were PowerShell logs available and useful?
7. Were network events adequately captured?
8. Were containment procedures effective?
9. Were escalation procedures followed?
10. What security controls should be improved?

---

# 8. Recommended Security Improvements

Potential improvements include:

- Strengthen authentication monitoring
- Enforce MFA where appropriate
- Review least-privilege controls
- Improve detection of repeated authentication failures followed by success
- Improve monitoring of privileged logons
- Monitor suspicious PowerShell behavior
- Monitor scheduled-task creation
- Correlate endpoint and network telemetry
- Tune SIEM detection rules based on lessons learned
- Maintain documented incident-response playbooks

---

# Incident Response Status

**Detection:** Completed

**Triage:** Completed

**Investigation:** Completed

**Classification:** True Positive within the simulated scenario

**Containment:** Recommended / simulated

**Eradication:** Recommended / simulated

**Recovery:** Recommended / simulated

**Post-Incident Review:** Recommended

---

## Portfolio Disclaimer

This incident-response plan documents actions that would be appropriate
for the simulated security scenario used in this portfolio.

Containment, eradication, and recovery actions described here are
recommendations within the lab scenario and should not be interpreted
as actions performed against a real production environment.
