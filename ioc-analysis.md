# Indicator and Artifact Analysis

## Objective

Identify and classify the security-relevant artifacts discovered during
the investigation and determine which require additional validation,
containment, or monitoring.

## Identified Artifacts

| Artifact | Type | Context | Assessment |
|---|---|---|---|
| jsmith | User Account | Account associated with suspicious authentication and follow-on activity | Affected account |
| WKSTN-104 | Endpoint | Host associated with authentication, process, network, and persistence events | Affected endpoint |
| 10.10.20.15 | Internal IP | Source associated with investigated activity | Investigation artifact |
| 203.0.113.50:443 | Network Destination | Outbound connection observed after suspicious process activity | Network artifact requiring validation |
| powershell.exe | Process | Executed shortly after privileged authentication | Suspicious in context |
| rundll32.exe | Process | Executed shortly after PowerShell | Suspicious in context |
| WindowsUpdateCheck | Scheduled Task | Created after suspicious process and network activity | Potential persistence artifact |
| EncodedCommand | PowerShell Artifact | Encoded PowerShell activity identified in later telemetry | High-interest execution artifact |
| SeDebugPrivilege | Privilege | Special privilege associated with the authenticated session | Privilege artifact |
| SeBackupPrivilege | Privilege | Special privilege associated with the authenticated session | Privilege artifact |

## Analyst Assessment

Not every artifact identified during an investigation should automatically
be classified as an Indicator of Compromise.

Processes such as `powershell.exe` and `rundll32.exe` are legitimate
Windows components that may also be abused.

Similarly, scheduled tasks and outbound HTTPS connections can represent
normal administrative activity.

Their significance in this investigation comes from the temporal
correlation between:

1. Repeated authentication failures
2. Successful authentication
3. Special privilege assignment
4. PowerShell execution
5. rundll32 execution
6. Outbound network communication
7. Scheduled task creation
8. Additional encoded PowerShell activity

The correlated sequence substantially increases the risk associated
with the individual artifacts.

## High-Priority Investigation Artifacts

The following artifacts should receive priority during incident response:

- Affected account: `jsmith`
- Affected endpoint: `WKSTN-104`
- Network destination: `203.0.113.50:443`
- Scheduled task: `WindowsUpdateCheck`
- PowerShell encoded-command activity

## Scope

Based on the available simulated evidence, the observed activity is
concentrated primarily around:

**Account:** `jsmith`

**Endpoint:** `WKSTN-104`

Additional enterprise-wide searches would be required to determine
whether the same artifacts appear on other systems or accounts.
