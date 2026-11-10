# Cyberion Detection Engineering — Telemetry Data Dictionary

## 1. Windows Sysmon Events

**Source:** EVTX-ATTACK-SAMPLES  
**Format:** Windows Event Log (.evtx)  
**Purpose:** Monitor endpoint process execution, registry modifications, network connections and process access.

| Field | Description | Relevant Event IDs |
|---|---|---|
| EventID | Sysmon event identifier | 1, 3, 10, 13 |
| UtcTime | Event timestamp in UTC | 1, 3, 10, 13 |
| Image | Executable image path | 1, 10 |
| CommandLine | Process command line | 1 |
| ParentImage | Parent process image | 1 |
| ProcessGuid | Unique process identifier | 1, 3, 10 |
| TargetImage | Target process image | 10 |
| GrantedAccess | Access rights requested against a process | 10 |
| TargetObject | Registry object modified | 13 |
| Details | Registry value or data associated with the event | 13 |
| User | Account associated with the event | 1, 10, 13 |

## 2. Windows Security Events

**Source:** EVTX-ATTACK-SAMPLES  
**Format:** Windows Security Event Log (.evtx)  
**Purpose:** Monitor account activity, authentication, object access and security group modifications.

| Field | Description | Relevant Event IDs |
|---|---|---|
| EventID | Security event identifier | 4624, 4663, 4702, 4732 |
| TimeCreated | Event timestamp | All |
| SubjectUserName | Account initiating an action | 4663, 4702, 4732 |
| SubjectLogonId | Logon session identifier | 4624, 4702 |
| TargetUserName | Account affected by an action | 4732 |
| MemberName | Account added to a security group | 4732 |
| ObjectName | Accessed object path | 4663 |
| ObjectType | Type of accessed object | 4663 |
| AccessMask | Requested access rights | 4663 |
| LogonType | Type of logon session | 4624 |
| IpAddress | Source IP address of a logon | 4624 |

## 3. Network Traffic (PCAP)

**Source:** EVTX-ATTACK-SAMPLES  
**Format:** Packet Capture (.pcap)  
**Analysis library:** dpkt  
**Purpose:** Examine network communication, DNS activity and potential command-and-control behaviour.

| Field | Description |
|---|---|
| Timestamp | Packet capture timestamp |
| Source IP | Originating IP address |
| Destination IP | Destination IP address |
| Source Port | Originating transport port |
| Destination Port | Destination transport port |
| DNS Query Name | Requested DNS domain |
| DNS Query Type | DNS record type |
| DNS Response | Returned DNS answer |
| DNS Transaction ID | Identifier linking DNS query and response |
| DNS Response Code | DNS response status |
| Packet Length | Captured packet size |

## 4. IIS Web Server Logs

**Source:** EVTX-ATTACK-SAMPLES  
**Format:** IIS 10.0 W3C Extended Log Format  
**Purpose:** Examine HTTP requests, suspicious endpoints and potential web-based tunnelling.

| Field | Description |
|---|---|
| date, time | Request timestamp |
| s-ip | Web server IP address |
| cs-method | HTTP request method |
| cs-uri-stem | Requested resource path |
| cs-uri-query | URL query parameters |
| s-port | Web server port |
| c-ip | Client IP address |
| cs(User-Agent) | Client user agent |
| sc-status | HTTP response status |
| sc-substatus | IIS substatus |
| sc-win32-status | Windows status code |
| time-taken | Request processing time in milliseconds |

## Data Dictionary Notes

- Field availability depends on the event ID, log configuration and source format.
- Not every event contains every listed field.
- Sysmon and Windows Security provide endpoint and audit telemetry.
- PCAP provides packet-level network telemetry.
- IIS provides application-layer HTTP request telemetry.
- Timestamps and identifiers should be normalized carefully when correlating events across sources.
- Sample IP addresses, domains and usernames are lab evidence, not automatically production IOCs.

