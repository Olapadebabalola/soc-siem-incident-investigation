# Network, PowerShell and Persistence Analysis

## Investigation Objective

Determine whether endpoint process execution, network communication,
and persistence activity following the suspicious authentication
indicates a potential security incident.

## Observed Activity

The investigation identified the following sequence on `WKSTN-104`:

| Time | Event ID | Activity | Indicator |
|---|---:|---|---|
| 09:02:44 | 4688 | PowerShell process created | powershell.exe |
| 09:03:02 | 4688 | rundll32.exe process created | rundll32.exe |
| 09:03:21 | 5156 | Outbound network connection | 203.0.113.50:443 |
| 09:04:01 | 4698 | Scheduled task created | WindowsUpdateCheck |

## Analysis

The events occurred shortly after the suspicious authentication and
privilege-assignment activity identified during the previous stages.

The sequence demonstrates:

1. PowerShell execution
2. Additional process execution through rundll32.exe
3. Outbound network communication
4. Creation of a scheduled task

The temporal relationship between these events increases the likelihood
that the activity is related to the original authentication event.

## Important Analyst Consideration

Individual events are not automatically malicious.

PowerShell, rundll32.exe, outbound HTTPS traffic, and scheduled tasks
can all have legitimate administrative purposes.

Therefore, these events are treated as suspicious based on their
sequence and context rather than being independently classified as
malicious.

## Current Assessment

**Classification:** Likely True Positive — pending final validation

**Severity:** High

**Affected Account:** jsmith

**Affected Host:** WKSTN-104

**Source IP:** 10.10.20.15

## Investigation Artifacts

Potential artifacts identified during the investigation include:

- `jsmith`
- `WKSTN-104`
- `10.10.20.15`
- `powershell.exe`
- `rundll32.exe`
- `203.0.113.50:443`
- `WindowsUpdateCheck`

## Recommended Next Actions

1. Validate whether the `jsmith` authentication was authorized.
2. Review PowerShell execution details and command-line information.
3. Investigate the origin and purpose of the scheduled task.
4. Validate the outbound destination against approved network activity.
5. Review endpoint telemetry for additional processes or indicators.
6. Determine whether other systems or accounts show similar activity.
7. If unauthorized activity is confirmed, contain the affected endpoint
   and account according to incident-response procedures.
