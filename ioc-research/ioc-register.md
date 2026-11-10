# Cyberion Detection Engineering — IOC Research and Register

## 1. Purpose

Document indicators observed during analysis of the supplied attack-focused telemetry and define how they could be investigated and operationalized in a real SOC environment.

## 2. IOC Register

| Indicator | Type | Associated Activity | Source | Confidence | Handling |
|---|---|---|---|---|---|
| ns.ostrykebs.pl | Domain | DNS TXT tunnelling | PCAP | High | Investigate and monitor |
| 192.168.100.121 | Internal IP | DNS TXT communication | PCAP | High | Lab-specific; investigate endpoint |
| 192.168.100.2 | Internal IP | DNS server involved in captured DNS exchanges | PCAP | High | Lab-specific; validate DNS role |
| 8.8.8.8 | External IP | External resolver observed in capture | PCAP | Informational | Do not classify as malicious based on this evidence |
| 10.0.2.17 | Internal IP | Client making HTTP tunnelling requests | IIS log | High | Lab-specific; investigate endpoint |
| 10.0.2.15 | Internal IP | IIS web server receiving tunnelling requests | IIS log | High | Lab-specific; investigate server |
| /erp/conn.aspx | URI path | Tunna HTTP tunnelling endpoint | IIS log | High | Investigate application and endpoint |
| 127.0.0.1:3389 | IP and port | Local RDP proxy destination | IIS log | High | Contextual indicator of tunnelling |

## 3. Indicator Analysis

### DNS Tunnelling

The PCAP contains repeated DNS TXT queries involving numbered subdomains under ns.ostrykebs.pl.

TXT responses contain Base64-encoded PowerShell content, including logic for retrieving and reconstructing commands.

This is consistent with DNS-based command retrieval.

### HTTP-Based RDP Tunnelling

The IIS log contains repeated requests to /erp/conn.aspx with the query:

proxy&port=3389&ip=127.0.0.1

This is consistent with HTTP requests being used to proxy traffic to the local RDP service.

## 4. IOC Operationalization

In a production SOC environment, the following actions could be taken:

1. Enrich domains and IP addresses using approved threat-intelligence sources.
2. Check DNS, proxy, firewall and endpoint telemetry for matching indicators.
3. Correlate indicators with process execution and authentication activity.
4. Apply domain or IP blocking only after validating ownership, reputation and business impact.
5. Monitor suspicious URI paths and proxy parameters in web-server logs.
6. Record indicator source, first-seen time, confidence and expiration or review date.
7. Update detection rules when new evidence supports additional detection logic.

## 5. False Positive and Context Considerations

- Private IP addresses in these samples are lab-specific and are not globally unique threat indicators.
- 8.8.8.8 is a public DNS resolver; its presence does not establish malicious activity.
- 127.0.0.1 is the localhost address and is not inherently malicious.
- Port 3389 is commonly used for legitimate RDP.
- URI paths can be legitimate in other environments.
- A domain observed in an old attack sample must be independently researched before being blocked.

## 6. Limitations

- The indicators originate from historical, attack-focused lab datasets.
- No current reputation or passive DNS enrichment has been performed.
- No production environment telemetry is available for validation.
- Confidence describes the indicator's relevance to the observed sample, not its current malicious reputation.

## 7. Conclusion

The investigation identified domain, IP, URI and network-service indicators associated with DNS and HTTP tunnelling.

These indicators have been documented with their source, context and recommended handling. They should be enriched and validated before operational blocking or deployment in a production threat-intelligence platform.
