# Incident Case Report 2: HTTP-Based RDP Tunnelling

## 1. Case Information

- Case ID: CYB-IR-002
- Incident Title: Suspicious HTTP-Based RDP Tunnelling
- Category: Protocol Tunnelling
- Severity: High
- Status: Closed - Lab Investigation
- Evidence Source: EVTX-ATTACK-SAMPLES
- Evidence File: Tunna_rdp_tunnel_IIS.log
- Log Format: IIS 10.0 W3C Extended Log Format

## 2. Executive Summary

The investigation identified suspicious HTTP activity consistent with the use of the Tunna tunnelling tool.

Repeated GET and POST requests targeted the IIS endpoint /erp/conn.aspx. The query parameters included proxy&port=3389&ip=127.0.0.1, indicating that the endpoint was configured to proxy traffic to the local RDP service.

The evidence supports HTTP-based RDP tunnelling behaviour. It does not independently confirm successful RDP authentication or lateral movement.

## 3. Timeline of Activity

| Timestamp (2019-09-03) | Observation |
|---|---|
| 10:13:36 | GET request with proxy parameters specifying port 3389 and 127.0.0.1 |
| 10:13:44 | POST and repeated GET requests to /erp/conn.aspx |
| 10:13:45 | Continued requests to the tunnelling endpoint |
| 10:13:47–10:13:49 | Repeated HTTP requests |
| 10:13:51 | Further GET and POST requests |

## 4. List of Affected Entities

| Entity | Value |
|---|---|
| Client IP | 10.0.2.17 |
| IIS server IP | 10.0.2.15 |
| Server port | 80 |
| Requested endpoint | /erp/conn.aspx |
| Proxy destination | 127.0.0.1 |
| Proxy destination port | 3389 |
| HTTP methods | GET, POST |
| HTTP status | 200 |

## 5. Detection and Investigation

The investigation examined IIS access logs for:

- Repeated requests to the same endpoint.
- Proxy-related query parameters.
- References to RDP port 3389.
- HTTP methods and response status codes.
- Client and server IP addresses.

The observed requests were consistent with the operation of the Tunna HTTP tunnelling tool.

## 6. MITRE ATT&CK Mapping

| Technique | Name | Tactic |
|---|---|---|
| T1572 | Protocol Tunneling | Command and Control |
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1071.001 | Web Protocols | Command and Control |

## 7. Root Cause Assessment

The supplied IIS sample is explicitly associated with the Tunna tunnelling tool.

The endpoint accepted HTTP requests containing parameters that specify a proxy destination of localhost port 3389.

The precise initial access method and the identity of the operator cannot be determined from the IIS logs alone.

## 8. Impact Assessment

**Potential impact: High**

HTTP tunnelling can allow RDP traffic to traverse networks where direct RDP connectivity is restricted.

Potential consequences include unauthorized remote access and lateral movement.

However, the available evidence confirms suspicious tunnelling activity, not a successful RDP session or compromise of another system.

## 9. Recommended Remediation

1. Investigate the client and IIS server.
2. Preserve IIS, Windows Security and network telemetry.
3. Review the /erp/conn.aspx application and its configuration.
4. Disable unauthorized proxy functionality.
5. Restrict unnecessary RDP access and enforce network segmentation.
6. Review authentication logs for unusual remote logons.
7. Investigate other endpoints for similar tunnelling activity.

## 10. Incident Closure

**Final classification:** True Positive - Suspicious HTTP tunnelling activity.

The behaviour was validated against the supplied attack-focused IIS sample. The investigation is closed as a completed lab case, with successful RDP authentication and lateral movement remaining unconfirmed.

