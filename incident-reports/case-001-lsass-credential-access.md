# Incident Case Report 1: Suspicious LSASS Memory Access

## 1. Case Information

- Case ID: CYB-IR-001
- Incident Title: Suspicious LSASS Memory Access
- Category: Credential Access
- Severity: High
- Status: Closed - Lab Investigation
- Evidence Source: EVTX-ATTACK-SAMPLES
- Evidence Files:
  - babyshark_mimikatz_powershell.evtx
  - sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx

## 2. Executive Summary

The investigation identified suspicious process access to the Local Security Authority Subsystem Service (LSASS).

Sysmon telemetry recorded PowerShell and Mimikatz-related activity accessing LSASS with GrantedAccess value 0x1010.

The observed behaviour is consistent with credential dumping attempts. The supplied telemetry confirms suspicious LSASS access but does not independently prove successful credential extraction.

## 3. Timeline of Activity

| Event | Evidence |
|---|---|
| Detection | Sysmon Event ID 10 identified LSASS process access |
| Investigation | GrantedAccess value 0x1010 examined |
| Correlation | Mimikatz-related process activity identified in a separate sample |
| Assessment | Activity classified as suspicious credential-access behaviour |
| Closure | Lab investigation documented and evidence preserved |

Exact timestamps should be taken from the corresponding EVTX event records when constructing a production incident timeline.

## 4. List of Affected Entities

| Entity | Value |
|---|---|
| Target process | lsass.exe |
| Suspicious process | PowerShell / Mimikatz-related process |
| Event source | Sysmon |
| Event ID | 10 |
| GrantedAccess | 0x1010 |
| Environment | Supplied Windows attack-simulation dataset |

## 5. Detection and Investigation

The investigation used two detection rules:

- Rule 1: Suspicious PowerShell Access to LSASS
- Rule 3: Mimikatz Accessing LSASS

Both rules matched their respective supplied attack samples.

The investigation focused on:
- Process access to lsass.exe.
- GrantedAccess value 0x1010.
- Suspicious process identity.
- Whether the observed activity was consistent with credential dumping.

## 6. MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|---|---|---|
| T1003 | OS Credential Dumping | Credential Access |
| T1003.001 | LSASS Memory | Credential Access |

## 7. Root Cause Assessment

The observed activity is consistent with an attempt to access LSASS memory using credential-access tooling.

The precise initial access vector and the identity of the operator cannot be established from the supplied LSASS access events alone.

## 8. Impact Assessment

**Potential impact: High**

Successful LSASS credential dumping could expose authentication material and enable subsequent unauthorized access.

However, the supplied evidence confirms suspicious LSASS access, not successful credential extraction, account compromise or lateral movement.

## 9. Recommended Remediation

1. Isolate the affected endpoint if similar activity is detected in a live environment.
2. Preserve Sysmon and Windows Security event logs.
3. Investigate the suspicious process and its parent process.
4. Review authentication activity for potentially compromised accounts.
5. Reset credentials if compromise is established.
6. Apply appropriate LSASS protection and endpoint security controls.
7. Investigate other endpoints for related activity.

## 10. Incident Closure

**Final classification:** True Positive - Suspicious credential-access activity.

The detection was validated against supplied attack telemetry. The incident is closed as a completed lab investigation, with successful credential extraction and downstream compromise remaining unconfirmed.

