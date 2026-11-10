# Correlation Rule 2 – MSHTA Execution and Network Connection

## Objective
Detect MSHTA executing an HTA file from the Internet cache and establishing a network connection from the same process.

## Dataset
EVTX-ATTACK-SAMPLES

File:
Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.evtx

## Detection Components
1. MSHTA Execution from Temporary Internet Files – Sysmon Event ID 1.
2. MSHTA Suspicious Outbound Network Connection – Sysmon Event ID 3.

## Test Results

| Validation | Result |
|---|---|
| Execution rule matched | True |
| Network rule matched | True |
| Same ProcessGuid | True |
| Time difference | 0.299 seconds |
| Within 30 seconds | True |
| Overall correlation | True |

## Observed Evidence
- Executable: mshta.exe
- HTA file: update.hta
- Execution location: Temporary Internet Files
- Destination IP: 10.0.2.18
- Destination port: 4443
- Both events shared the same ProcessGuid.

## MITRE ATT&CK
- T1218.005 – System Binary Proxy Execution: Mshta
- Tactic: Defense Evasion

## Limitations
- Port 4443 is specific to this validation sample and is not universally malicious.
- Destination IP 10.0.2.18 is a private IP observed in the lab sample, not a confirmed public IOC.
- Sigma temporal correlation does not enforce event order.
- Generated Splunk SPL uses fixed 30-second time buckets rather than a precise sliding window.
- Benign false-positive validation is pending.

## Conclusion
Both component detections matched the sample. The events shared the same process GUID and occurred 0.299 seconds apart, satisfying the 30-second correlation condition.
