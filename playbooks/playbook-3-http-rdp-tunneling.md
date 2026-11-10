# Incident Response Playbook 3: HTTP-Based RDP Tunnelling

## 1. Purpose

Provide a structured response to suspected RDP tunnelling through HTTP or unauthorized web-based proxy endpoints.

## 2. Trigger Conditions

Initiate this playbook when:
- IIS logs show repeated requests to suspicious proxy endpoints.
- HTTP query parameters reference internal services or RDP port 3389.
- Unusual GET and POST request patterns are observed.
- Network telemetry indicates possible RDP traffic being tunnelled through HTTP.
- Suspicious web-based tunnelling tools are identified.

## 3. Investigation

1. Identify the client IP and web-server IP.
2. Examine IIS fields including cs-uri-stem, cs-uri-query, cs-method and sc-status.
3. Identify repeated requests to the same endpoint.
4. Investigate query parameters referencing internal IP addresses and port 3389.
5. Review IIS application configuration and deployed scripts.
6. Correlate web requests with Windows Security logon events and network connections.
7. Determine whether an RDP session was actually established.
8. Investigate the client and server for additional compromise indicators.

## 4. Containment

- Restrict access to confirmed unauthorized proxy endpoints.
- Isolate affected systems when active compromise is suspected.
- Block unauthorized remote access paths through approved network controls.
- Preserve IIS, endpoint and network logs.
- Restrict RDP access to approved systems and users.

## 5. Eradication

- Remove unauthorized tunnelling tools and web shells.
- Remove malicious application components and configuration changes.
- Identify and remediate the original compromise vector.
- Review web-server permissions and application security.
- Remove unauthorized remote-access mechanisms.

## 6. Recovery

- Restore affected web applications from trusted backups if necessary.
- Validate IIS configuration and application integrity.
- Re-enable approved network connectivity after security checks.
- Monitor HTTP requests for repeated proxy patterns.
- Review RDP authentication and connection activity.

## 7. Stakeholder Communication

Notify:
- SOC analyst or incident handler.
- Network security team.
- Web-server and application administrators.
- Endpoint security team.
- IT operations and security management.

Communications should include affected systems, suspicious endpoints, evidence, containment actions and unresolved risks.

## 8. Closure Criteria

- Suspicious HTTP tunnelling activity has been investigated.
- The affected web application and endpoints have been assessed.
- Unauthorized proxy functionality has been removed or restricted.
- RDP access has been reviewed.
- Recovery and monitoring checks are complete.
- Evidence and incident findings are documented.

## 9. Relevant MITRE ATT&CK Techniques

- T1572 - Protocol Tunneling
- T1021.001 - Remote Desktop Protocol
- T1071.001 - Web Protocols

