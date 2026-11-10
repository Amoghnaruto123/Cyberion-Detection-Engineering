# Incident Response Playbook 1: LSASS Credential Dumping

## 1. Purpose

Provide a structured response to suspected credential dumping involving the Local Security Authority Subsystem Service (LSASS).

## 2. Trigger Conditions

Initiate this playbook when:
- Sysmon Event ID 10 identifies suspicious access to lsass.exe.
- GrantedAccess indicates potentially suspicious memory access, such as 0x1010.
- Mimikatz or another credential-access tool is identified.
- Multiple credential-access indicators occur on the same endpoint.

## 3. Investigation

1. Identify the source process accessing lsass.exe.
2. Examine ProcessGuid, Image, ParentImage and CommandLine.
3. Review GrantedAccess and the event timestamp.
4. Investigate related process creation events (Sysmon Event ID 1).
5. Check for suspicious PowerShell activity.
6. Review authentication logs for unusual account usage.
7. Determine whether credential extraction or subsequent access is supported by evidence.

## 4. Containment

- Isolate the affected endpoint using approved endpoint security controls when compromise is suspected.
- Restrict suspicious processes and accounts where justified.
- Preserve relevant endpoint and authentication logs.
- Avoid shutting down or modifying the system before evidence-preservation requirements are considered.

## 5. Eradication

- Remove confirmed malicious tools and persistence mechanisms.
- Identify and remediate the original compromise vector.
- Reset potentially exposed credentials after assessing the scope.
- Review endpoint security configuration and LSASS protection.

## 6. Recovery

- Restore the endpoint from a trusted state if required.
- Reconnect the system only after security checks.
- Monitor for repeated LSASS access and suspicious authentication.
- Validate that security controls are operating correctly.

## 7. Stakeholder Communication

Notify:
- SOC analyst or incident handler.
- Security operations lead.
- Endpoint or IT operations team.
- Identity and access management team when credentials may be exposed.
- Relevant management according to incident severity.

Communications should include affected systems, evidence, severity, containment status and outstanding risks.

## 8. Closure Criteria

- Suspicious LSASS access has been investigated.
- The scope of potential credential exposure has been assessed.
- Required containment and remediation actions are complete.
- Credentials have been reset where justified.
- Monitoring is in place.
- Evidence and incident findings are documented.

## 9. Relevant MITRE ATT&CK Techniques

- T1003 - OS Credential Dumping
- T1003.001 - LSASS Memory

