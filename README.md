# SIEM Security Incident Investigation

## Executive Summary

This project demonstrates a Security Operations Center (SOC) investigation of suspicious authentication activity using Security Information and Event Management (SIEM) principles.

The investigation focuses on alert triage, security log analysis, event correlation, true/false-positive classification, Indicator of Compromise (IOC) identification, incident investigation, containment, and remediation.

> **Project Type:** Hands-on cybersecurity portfolio project  
> **Environment:** Simulated/Lab Environment  
> **Focus:** SOC Operations and Incident Response

---

## Objective

The objective of this investigation is to determine whether suspicious authentication activity represents a legitimate security event or a potential compromise.

The investigation will:

- Analyze security alerts and authentication logs
- Correlate related security events
- Determine whether an alert is a true or false positive
- Identify Indicators of Compromise (IOCs)
- Determine the potential scope and impact of the activity
- Recommend appropriate containment actions
- Document remediation and lessons learned

---

## Tools & Technologies

- Splunk
- Microsoft Sentinel
- SIEM
- Security Event Logs
- Windows Authentication Logs
- IOC Analysis
- Incident Response Methodology

---

## Investigation Scenario

An organization detects multiple failed authentication attempts against a user account followed by a successful authentication from an unusual source.

The SOC analyst is responsible for determining:

1. Whether the activity is legitimate or malicious
2. Whether the alert is a true or false positive
3. What systems and accounts may be affected
4. Whether any Indicators of Compromise are present
5. What containment and remediation actions should be taken

---

## Investigation Methodology

The investigation follows this workflow:

```text
Security Alert
      ↓
Initial Triage
      ↓
Log Analysis
      ↓
Event Correlation
      ↓
True / False Positive Classification
      ↓
IOC Identification
      ↓
Scope Determination
      ↓
Containment
      ↓
Remediation
      ↓
Lessons Learned
