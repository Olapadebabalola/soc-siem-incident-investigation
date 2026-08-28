# MITRE ATT&CK Mapping

## Objective

Map the behaviors observed during the simulated SOC investigation to
relevant MITRE ATT&CK techniques.

The mappings below are based only on behaviors supported by the
simulated dataset. They are intended to demonstrate how SOC analysts
can use ATT&CK to describe and communicate observed adversary-like
behavior.

---

## ATT&CK Technique Mapping

| Observed Behavior | Evidence | MITRE ATT&CK Technique | Technique ID | Assessment |
|---|---|---|---|---|
| Repeated failed authentication followed by success | Windows authentication events 4625 and 4624 | Brute Force | T1110 | Possible / contextual |
| PowerShell execution | powershell.exe and PowerShell telemetry | PowerShell | T1059.001 | Supported |
| rundll32.exe execution | Process creation event | System Binary Proxy Execution: Rundll32 | T1218.011 | Possible / requires command-line validation |
| Scheduled task creation | WindowsUpdateCheck | Scheduled Task/Job: Scheduled Task | T1053.005 | Supported |
| Encoded PowerShell activity | PowerShell EncodedCommand | PowerShell | T1059.001 | Supported |

---

# 1. Authentication Activity

## Potential Technique

**T1110 — Brute Force**

### Evidence

The dataset contains multiple failed authentication attempts against
the `jsmith` account followed shortly by a successful authentication.

### Analyst Assessment

This pattern is consistent with activity that may warrant investigation
for brute-force or password-guessing behavior.

However, the authentication pattern alone does not prove that brute
force occurred.

Additional evidence such as authentication source history, user
validation, password-spray patterns, and broader account activity would
be required for stronger attribution.

**Mapping confidence:** Moderate / contextual

---

# 2. PowerShell Execution

## Technique

**T1059.001 — Command and Scripting Interpreter: PowerShell**

### Evidence

PowerShell execution was observed after the investigated authentication
and privilege activity.

Additional PowerShell script-block telemetry contained an
`EncodedCommand` indicator.

### Analyst Assessment

PowerShell is a legitimate administrative tool and its execution alone
is not malicious.

In this scenario, its significance comes from its position within the
larger sequence of suspicious authentication, privilege, process,
network, and persistence events.

**Mapping confidence:** High for observed PowerShell execution.

---

# 3. Rundll32 Execution

## Potential Technique

**T1218.011 — System Binary Proxy Execution: Rundll32**

### Evidence

The dataset records execution of:

`rundll32.exe`

shortly after PowerShell execution.

### Analyst Assessment

Rundll32 is a legitimate Windows utility.

The dataset confirms execution of the binary but does not provide the
DLL, export, command-line arguments, or parent-child process details
needed to prove proxy execution of malicious content.

Therefore, the technique is recorded as a potential mapping requiring
additional validation.

**Mapping confidence:** Moderate / requires additional telemetry.

---

# 4. Scheduled Task Persistence

## Technique

**T1053.005 — Scheduled Task/Job: Scheduled Task**

### Evidence

The investigation identified creation of the scheduled task:

`WindowsUpdateCheck`

The dataset later shows activity associated with the scheduled task
under the SYSTEM context.

### Analyst Assessment

Scheduled tasks are commonly used for legitimate administration but
may also be used to maintain execution or persistence.

Within the simulated scenario, the timing of task creation and later
SYSTEM-associated activity makes the task a high-priority persistence
artifact.

**Mapping confidence:** High for scheduled-task creation.

---

# 5. Network Communication

The dataset records outbound communication to:

`203.0.113.50:443`

following process execution.

This network activity is relevant to the investigation, but the
available evidence does not establish the application-layer protocol,
remote infrastructure purpose, command-and-control behavior, or data
transfer characteristics.

Therefore, this portfolio does not assign a specific MITRE ATT&CK
Command and Control technique based solely on the outbound connection.

Additional proxy, DNS, firewall, packet, or EDR network telemetry would
be required.

---

# ATT&CK Investigation Summary

The strongest ATT&CK-supported behaviors identified in the simulated
investigation are:

- T1059.001 — PowerShell
- T1053.005 — Scheduled Task/Job: Scheduled Task

Additional contextual or potential mappings include:

- T1110 — Brute Force
- T1218.011 — System Binary Proxy Execution: Rundll32

The investigation intentionally avoids assigning ATT&CK techniques when
the available simulated telemetry does not provide sufficient evidence.

---

## Portfolio Note

This ATT&CK mapping is based on a simulated SOC investigation and is
intended to demonstrate security-event analysis, behavioral
correlation, and threat-framework mapping.

The mapping does not represent attribution to a real threat actor or
analysis of a real production compromise.
