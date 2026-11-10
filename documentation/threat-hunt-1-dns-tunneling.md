# Threat Hunt 1: Detecting DNS Tunnelling Through TXT Records

## 1. Hunt Overview

**Hunt type:** Hypothesis-driven network threat hunt  
**Data source:** EVTX-ATTACK-SAMPLES PCAP  
**Evidence file:** cmds over dns txt queries and reponses.pcap  
**MITRE ATT&CK:** T1071.004 - Application Layer Protocol: DNS  
**Related technique:** T1059.001 - PowerShell

## 2. Hypothesis

An endpoint may be using DNS TXT records to retrieve encoded PowerShell commands, potentially establishing a covert command-and-control channel.

## 3. Hunt Objectives

- Identify unusual DNS TXT record activity.
- Investigate repeated queries to numbered subdomains.
- Identify encoded content in DNS responses.
- Determine whether the observed traffic is consistent with DNS-based command-and-control.

## 4. Data Collection and Scope

The supplied PCAP was examined using Python and the dpkt library.

Observed capture statistics:
- Total packets: 301
- DNS packets: 199
- Link type: Ethernet
- Internal host: 192.168.100.121
- DNS server: 192.168.100.2
- External resolver observed: 8.8.8.8
- Domain: ns.ostrykebs.pl

## 5. Investigation Methodology

The investigation examined:

1. DNS query names and record types.
2. DNS TXT responses.
3. Repeated and sequential subdomain patterns.
4. Encoded content returned in DNS responses.
5. Communication patterns between the internal host and DNS server.

Captured content was inspected as untrusted data. No recovered commands or payloads were executed.

## 6. Findings

### Finding 1: Sequential DNS queries

Queries included numbered subdomains such as:

- l.1.ns.ostrykebs.pl
- l.2.ns.ostrykebs.pl
- l.3.ns.ostrykebs.pl
- Continuing through l.17.ns.ostrykebs.pl

This pattern is unusual and warrants investigation.

### Finding 2: Encoded PowerShell content

DNS TXT responses contained Base64-encoded PowerShell content.

The observed script logic retrieves successive TXT responses, decodes their contents and reconstructs a PowerShell command string.

### Finding 3: Command execution behaviour

The recovered script logic included an invocation using PowerShell Invoke-Expression (IEX).

This indicates that the DNS responses were intended to supply commands for execution rather than merely return ordinary DNS information.

### Finding 4: Network communication

The capture showed DNS communication involving:

- Endpoint: 192.168.100.121
- DNS server: 192.168.100.2

The external resolver 8.8.8.8 was also observed in the capture. Its presence alone does not establish that it was the command-and-control destination.

## 7. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1071.004 | DNS | DNS used to transport command content |
| T1059.001 | PowerShell | PowerShell commands retrieved and invoked |
| T1105 | Ingress Tool Transfer | Potential command or content retrieval; requires further validation |

## 8. Hunt Conclusion

**Assessment: Suspicious activity identified.**

The combination of sequential DNS subdomain queries, encoded TXT responses and PowerShell command reconstruction is consistent with DNS tunnelling used for command-and-control.

The evidence supports identifying the activity as suspicious DNS-based command delivery. It does not independently establish successful execution of every retrieved command, data exfiltration or the identity of an external command-and-control operator.

## 9. Recommended Investigation and Response

- Isolate the affected endpoint if this activity is observed in a live environment and the incident response process authorizes it.
- Preserve DNS, endpoint and network telemetry.
- Investigate PowerShell process creation and parent-child relationships.
- Review DNS queries for the observed domain and related subdomains.
- Determine whether similar activity occurred on other endpoints.
- Block confirmed malicious infrastructure through approved security controls.
- Perform endpoint investigation before restoring normal connectivity.

## 10. Limitations

- The PCAP is a small attack-focused sample, not representative enterprise baseline traffic.
- No production DNS baseline was available for comparison.
- The capture alone cannot establish the complete endpoint execution history.
- Observed IP addresses and domain are sample-specific and should not automatically be treated as current IOCs.

