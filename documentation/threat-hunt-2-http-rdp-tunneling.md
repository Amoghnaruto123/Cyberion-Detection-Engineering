# Threat Hunt 2: Detecting RDP Tunnelling Through HTTP

## 1. Hunt Overview

**Hunt type:** Hypothesis-driven web and network threat hunt  
**Data source:** EVTX-ATTACK-SAMPLES  
**Evidence file:** Tunna_rdp_tunnel_IIS.log  
**Log format:** IIS 10.0 W3C Extended Log Format  
**MITRE ATT&CK:** T1572 - Protocol Tunneling  
**Related technique:** T1021.001 - Remote Desktop Protocol

## 2. Hypothesis

An attacker may be tunnelling Remote Desktop Protocol (RDP) traffic through HTTP requests to bypass network restrictions and access an internal RDP service.

## 3. Hunt Objectives

- Identify suspicious HTTP endpoints and query parameters.
- Detect repeated requests that may indicate tunnelling.
- Identify references to internal services and RDP port 3389.
- Determine whether the web-server activity is consistent with HTTP-based RDP tunnelling.

## 4. Data Collection and Scope

The investigation examined the IIS log sample associated with the Tunna tunnelling tool.

Observed details:
- Web server IP: 10.0.2.15
- Client IP: 10.0.2.17
- Server port: 80
- Requested endpoint: /erp/conn.aspx
- HTTP methods: GET and POST
- HTTP response status: 200
- Suspicious query: proxy&port=3389&ip=127.0.0.1

## 5. Investigation Methodology

The following IIS fields were examined:

- date and time
- s-ip
- cs-method
- cs-uri-stem
- cs-uri-query
- s-port
- c-ip
- sc-status
- time-taken

The investigation focused on repeated requests to the same endpoint, proxy-related parameters and references to the RDP service.

## 6. Findings

### Finding 1: Suspicious proxy parameters

The following query was observed:

proxy&port=3389&ip=127.0.0.1

Port 3389 is associated with RDP. The parameters indicate that the endpoint is configured to proxy traffic to the local RDP service.

### Finding 2: Repeated HTTP requests

Multiple GET and POST requests targeted:

/erp/conn.aspx

The repeated requests occurred within a short period, consistent with an application endpoint being used to relay traffic.

### Finding 3: Successful HTTP responses

The observed requests returned HTTP status 200.

This indicates successful HTTP responses from the web server, although it does not independently prove that an RDP session was successfully established.

### Finding 4: Client and server relationship

The IIS logs identify:
- Client: 10.0.2.17
- Server: 10.0.2.15

The activity is consistent with a client communicating with a web endpoint that proxies traffic to localhost port 3389.

## 7. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1572 | Protocol Tunneling | RDP traffic is proxied through HTTP |
| T1021.001 | Remote Desktop Protocol | The proxied destination is RDP port 3389 |
| T1071.001 | Web Protocols | HTTP is used as the transport mechanism |

## 8. Hunt Conclusion

**Assessment: Suspicious tunnelling activity identified.**

The proxy parameters, RDP port reference and repeated HTTP requests are consistent with Tunna-based HTTP tunnelling.

The IIS logs provide evidence of the tunnelling mechanism, but do not independently confirm that a complete RDP session was established or that a successful lateral movement operation occurred.

## 9. Recommended Investigation and Response

- Investigate the client endpoint 10.0.2.17.
- Review web-server activity involving /erp/conn.aspx.
- Correlate IIS requests with endpoint process and network telemetry.
- Check whether RDP connections were established on the destination system.
- Review authentication events for unusual remote logons.
- Preserve relevant IIS, Windows Security and network logs.
- Restrict unauthorized proxy endpoints and investigate the application configuration.

## 10. Limitations

- The sample is attack-focused and does not provide normal IIS traffic for baseline comparison.
- HTTP 200 responses do not prove successful RDP authentication.
- No corresponding RDP session telemetry was supplied with this IIS log.
- The IP addresses and endpoint are sample-specific and should not automatically be treated as current IOCs.

