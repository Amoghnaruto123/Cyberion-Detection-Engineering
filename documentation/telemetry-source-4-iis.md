# Telemetry Source 4: IIS Web Server Logs

## Source
- Dataset: EVTX-ATTACK-SAMPLES
- File: Tunna_rdp_tunnel_IIS.log
- Format: IIS 10.0 W3C Extended Log Format
- Date: 2019-09-03

## Observed Telemetry
- Web server IP: 10.0.2.15
- Client IP: 10.0.2.17
- Server port: 80
- Requested endpoint: /erp/conn.aspx
- HTTP methods: GET and POST
- HTTP status: 200
- Suspicious query parameters: proxy&port=3389&ip=127.0.0.1

## Suspicious Behaviour
Repeated HTTP GET and POST requests target the same ASP.NET endpoint.
The query parameters specify port 3389 and localhost (127.0.0.1), indicating that HTTP requests are being used to proxy traffic to the local RDP service.

This activity is consistent with Tunna-based HTTP tunnelling.

## Relevant Log Fields

| Field | Description |
|---|---|
| date, time | Request timestamp |
| s-ip | Web server IP address |
| cs-method | HTTP method |
| cs-uri-stem | Requested resource |
| cs-uri-query | URL query parameters |
| s-port | Server port |
| c-ip | Client IP address |
| cs(User-Agent) | Client user agent |
| sc-status | HTTP response status |
| sc-substatus | IIS substatus |
| sc-win32-status | Windows status code |
| time-taken | Request processing time in milliseconds |

## Detection Opportunities
- Repeated requests to unusual ASP.NET endpoints.
- HTTP requests containing proxy parameters.
- Requests referencing internal services such as RDP port 3389.
- Unusual GET and POST request patterns.
- Repeated successful HTTP responses associated with tunnelling endpoints.

## Limitations
This is an attack-focused IIS log sample, not representative baseline web-server traffic.
The observed IP addresses and endpoint belong to the supplied lab dataset and should not automatically be treated as current indicators of compromise.
