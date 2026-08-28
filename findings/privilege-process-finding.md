# Privilege and Process Analysis

## Investigation Objective

Determine whether activity following the successful authentication
indicates privileged execution, suspicious process activity, network
communication, or persistence.

## Observed Activity

The investigation identified the following sequence on `WKSTN-104`:

| Time | Event ID | Activity |
|---|---:|---|
| 09:02:03 | 4624 | Successful authentication |
| 09:02:15 | 4672 | Special privileges assigned |
| 09:02:44 | 4688 | PowerShell process created |
| 09:03:02 | 4688 | rundll32.exe process created |
| 09:03:21 | 5156 | Outbound connection to 203.0.113.50:443 |
| 09:04:01 | 4698 | Scheduled task created |

## Analysis

The sequence is more concerning than the authentication activity alone.

A successful authentication was followed within seconds by privileged
activity and process creation. Network communication and creation of a
scheduled task occurred shortly afterward.

The combination of authentication, privilege assignment, process
execution, network communication, and persistence warrants escalation
for further incident investigation.

## Current Assessment

**Classification:** Suspicious / likely security incident

**Severity:** High

**Affected Account:** jsmith

**Affected Host:** WKSTN-104

**Source IP:** 10.10.20.15

## Potential Investigation Artifacts

- `jsmith`
- `WKSTN-104`
- `10.10.20.15`
- `203.0.113.50:443`
- `powershell.exe`
- `rundll32.exe`
- `WindowsUpdateCheck`
- `SeDebugPrivilege`
- `SeBackupPrivilege`

## Next Investigation Step

Investigate:

1. The outbound network connection
2. PowerShell activity
3. The scheduled task
4. Whether the external address represents a known or suspicious destination
5. Whether the activity is consistent with an unauthorized account compromise
