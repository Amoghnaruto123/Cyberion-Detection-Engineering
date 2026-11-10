# Cyberion Detection Engineering — MITRE ATT&CK Coverage Matrix

This matrix tracks implemented detections, correlation detections and potential threat-hunting coverage.

**Status definitions**
- Implemented: A standalone detection rule has been created and tested against attack telemetry.
- Correlation: A correlation rule has been created and tested against attack telemetry.
- Hunt candidate: A technique identified for future hypothesis-driven threat hunting.
- Planned: No detection or hunt has been completed yet.

| MITRE Technique ID | Technique | Tactic | Coverage | Status |
|---|---|---|---|---|
| T1003 | OS Credential Dumping | Credential Access | LSASS access detection | Implemented |
| T1003.001 | LSASS Memory | Credential Access | PowerShell and Mimikatz LSASS access | Implemented |
| T1059.003 | Windows Command Shell | Execution | FTP-to-CMD execution | Implemented |
| T1218.011 | Rundll32 | Defense Evasion | Suspicious file protocol handler | Implemented |
| T1218.010 | Regsvr32 | Defense Evasion | Renamed Regsvr32 scriptlet | Implemented |
| T1218.005 | Mshta | Defense Evasion | Mshta from Internet cache | Implemented |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | Run key and startup folder modifications | Implemented |
| T1136.001 | Create Account: Local Account | Persistence | Hidden local account creation | Implemented |
| T1569.002 | Service Execution | Execution | Hidden PowerShell through service configuration | Implemented |
| T1053.005 | Scheduled Task | Persistence | Remote logon and task modification correlation | Correlation |
| T1078 | Valid Accounts | Initial Access | Suspicious account usage | Hunt candidate |
| T1110 | Brute Force | Credential Access | Repeated authentication failures | Hunt candidate |
| T1555 | Credentials from Password Stores | Credential Access | Credential-store access | Planned |
| T1059.001 | PowerShell | Execution | Suspicious PowerShell command execution | Hunt candidate |
| T1105 | Ingress Tool Transfer | Command and Control | Suspicious tool download activity | Hunt candidate |
| T1071.001 | Web Protocols | Command and Control | HTTP-based command-and-control activity | Hunt candidate |
| T1071.004 | DNS | Command and Control | DNS TXT tunnelling | Hunt candidate |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Data transfer through command-and-control channel | Hunt candidate |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | RDP tunnelling activity | Hunt candidate |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Suspicious SMB-based remote activity | Hunt candidate |
| T1018 | Remote System Discovery | Discovery | Remote host discovery | Planned |
| T1087.001 | Account Discovery: Local Account | Discovery | Local account enumeration | Planned |
| T1098 | Account Manipulation | Persistence | Account permission and configuration changes | Planned |
| T1112 | Modify Registry | Defense Evasion | Suspicious registry modification | Hunt candidate |
| T1055 | Process Injection | Defense Evasion | Suspicious process injection | Planned |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | Security tool modification | Planned |

## Coverage Summary

- Standalone detection rules: 12
- Correlation detection rules: 3
- Total implemented detection rules: 15
- ATT&CK techniques and sub-techniques listed: 26
- Tactics represented: 9

## Coverage Notes

- Implemented and correlation statuses refer to rules tested against supplied attack telemetry.
- Hunt candidates are areas identified for further investigation, not completed hunts.
- Planned techniques do not currently have validated detections.
- Some techniques belong to multiple ATT&CK tactics; this matrix uses the primary tactic relevant to the proposed detection or hunt.
- Technique coverage should be updated as additional detections and hunts are completed.

