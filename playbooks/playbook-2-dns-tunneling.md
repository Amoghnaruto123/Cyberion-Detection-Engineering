# Incident Response Playbook 2: DNS Tunnelling and Command-and-Control

## 1. Purpose

Provide a structured response to suspected DNS tunnelling used for command retrieval, covert communication or command-and-control activity.

## 2. Trigger Conditions

Initiate this playbook when:
- An endpoint generates unusually frequent DNS TXT queries.
- Sequential or numbered DNS subdomains are observed.
- DNS responses contain unusually large or encoded content.
- DNS activity is associated with suspicious PowerShell execution.
- DNS tunnelling detection rules generate alerts.

## 3. Investigation

1. Identify the affected endpoint and DNS resolver.
2. Examine DNS query names, record types and response sizes.
3. Identify repeated or sequential subdomain patterns.
4. Investigate suspicious domains and related DNS infrastructure.
5. Inspect encoded DNS responses safely without executing recovered content.
6. Correlate DNS activity with Sysmon process creation and network events.
7. Determine whether command retrieval, execution or data transfer is supported by evidence.

## 4. Containment

- Isolate the affected endpoint when active compromise is suspected.
- Restrict confirmed malicious DNS destinations through approved controls.
- Preserve DNS resolver logs and packet captures.
- Prevent unauthorized DNS traffic where network policy permits.
- Avoid blocking shared infrastructure without validating its impact.

## 5. Eradication

- Remove confirmed malicious scripts, tools and persistence mechanisms.
- Identify and remediate the initial compromise vector.
- Review PowerShell execution controls.
- Remove unauthorized scheduled tasks or registry modifications.
- Investigate other endpoints for similar DNS activity.

## 6. Recovery

- Restore affected systems from trusted sources where necessary.
- Re-enable network connectivity after security validation.
- Monitor DNS TXT activity and unusual subdomain patterns.
- Confirm endpoint security controls are functioning correctly.

## 7. Stakeholder Communication

Notify:
- SOC analyst or incident handler.
- Network security team.
- DNS and infrastructure administrators.
- Endpoint security team.
- Security operations lead and relevant management.

Communications should include affected endpoints, suspicious domains, DNS patterns, containment actions and outstanding risks.

## 8. Closure Criteria

- Suspicious DNS activity has been investigated.
- Affected endpoints and related infrastructure have been assessed.
- Malicious activity has been contained and remediated.
- DNS and endpoint monitoring is in place.
- Evidence and findings are documented.

## 9. Relevant MITRE ATT&CK Techniques

- T1071.004 - Application Layer Protocol: DNS
- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer

