# Final Incident Classification

## Classification

**Alert Classification:** True Positive

**Incident Severity:** High

**Incident Type:** Suspected Account Compromise with Post-Authentication Activity

**Affected Account:** jsmith

**Affected Endpoint:** WKSTN-104

## Evidence Supporting Classification

The alert was classified as a True Positive based on the correlation
of multiple security events rather than any single indicator.

The investigation identified:

1. Multiple failed authentication attempts
2. Successful authentication shortly after the failures
3. Special privilege assignment
4. PowerShell execution
5. rundll32.exe execution
6. Outbound network communication
7. Scheduled-task creation
8. Continued scheduled-task/network activity
9. Encoded PowerShell activity

## Analyst Determination

The combined activity is inconsistent with an isolated failed-login
alert and demonstrates a broader sequence of suspicious
post-authentication behavior.

Within the simulated scenario, the correlation between authentication,
privileged execution, process activity, persistence, and continued
network communication provides sufficient evidence to classify the
security alert as a True Positive requiring incident response.

## Scope Determination

Current evidence identifies:

- One affected user account: `jsmith`
- One affected endpoint: `WKSTN-104`
- One network destination requiring investigation: `203.0.113.50:443`
- One potential persistence mechanism: `WindowsUpdateCheck`

The available dataset does not establish whether additional enterprise
systems are affected.

A real-world investigation would require broader SIEM and EDR searches
across the environment before declaring the incident fully scoped.

## Recommended Disposition

**Escalate to Incident Response.**

Recommended immediate actions include:

- Protect or temporarily disable the affected account according to policy
- Isolate the affected endpoint if operationally appropriate
- Investigate the scheduled task
- Review PowerShell command-line/script-block telemetry
- Validate the external network destination
- Search enterprise telemetry for matching artifacts
- Preserve relevant logs and endpoint evidence
- Reset credentials if unauthorized account access is confirmed
- Remove unauthorized persistence after evidence preservation
