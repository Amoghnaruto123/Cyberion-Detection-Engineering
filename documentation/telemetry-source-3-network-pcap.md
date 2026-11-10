# Telemetry Source 3: Network Traffic (PCAP)

## Source
- Dataset: EVTX-ATTACK-SAMPLES
- File: cmds over dns txt queries and reponses.pcap
- Format: PCAP
- File size: 36,173 bytes
- Analysis library: dpkt 1.9.8

## Observed Telemetry
- Total packets: 301
- DNS packets: 199
- Link type: Ethernet
- Internal host: 192.168.100.121
- DNS server: 192.168.100.2
- External DNS resolver: 8.8.8.8
- Observed domain: ns.ostrykebs.pl
- DNS record type: TXT

## Suspicious Behaviour
DNS TXT responses contain Base64-encoded PowerShell content.
Repeated numbered DNS subdomain queries retrieve command content.
The captured script includes logic for sending command results through DNS TXT records.

This behaviour is consistent with DNS tunnelling and command-and-control communication.

## Relevant Network Fields

| Field | Description |
|---|---|
| Timestamp | Packet capture timestamp |
| Source IP | Originating IP address |
| Destination IP | Destination IP address |
| Source Port | Originating transport port |
| Destination Port | Destination transport port |
| DNS Query Name | Requested DNS domain |
| DNS Query Type | DNS record type requested |
| DNS Response | Returned DNS answer |
| DNS Transaction ID | Identifier linking DNS query and response |
| DNS Response Code | DNS response status |
| Packet Length | Captured packet size |

## Detection Opportunities
- Unusual DNS TXT record activity.
- Repeated queries to suspicious domains.
- Sequential or numbered subdomain patterns.
- Large or encoded DNS TXT responses.
- DNS traffic associated with suspicious endpoint processes.

## Limitations
This is a small, attack-focused PCAP rather than representative enterprise baseline traffic.
The observed IP addresses and domain belong to the supplied lab capture and should not automatically be treated as current indicators of compromise.
