# Correlation Rule 3 – Network Logon Followed by Scheduled Task Modification

## Objective
Identify a successful Windows network logon followed by a scheduled task modification under the same logon session.

## Detection Logic
- Event ID 4624: Successful network logon (LogonType 3).
- Event ID 4702: Scheduled task modification.
- Correlation key: TargetLogonId from Event 4624 and SubjectLogonId from Event 4702.
- Time constraint: Events must occur within 60 seconds.
- MITRE ATT&CK: T1053.005 – Scheduled Task.

## Test Dataset
EVTX-ATTACK-SAMPLES:
Lateral Movement/remote task update 4624 4702 same logonid.evtx

## Observed Evidence

| Field | Value |
|---|---|
| Account | a-jbrown |
| Logon ID | 0x21a8c68 |
| Logon Type | 3 (Network) |
| Source IP | 172.16.66.142 |
| Logon Event | 4624 |
| Task Modification Event | 4702 |
| Scheduled Task | \LMST |
| Time Difference | 0.389 seconds |
| Correlation Result | CORRELATED |

## Scheduled Task Details
- Task name: \LMST
- Hidden: True
- Run level: HighestAvailable
- Configured execution account: SYSTEM
- Command: cmd.exe
- Arguments: /c echo testing > c:\users\public\out.txt

## Test Result
PASS – The test successfully correlated Event ID 4624 and Event ID 4702 using the shared Logon ID within the 60-second time constraint.

## Analysis
The matching Logon ID establishes that both events belong to the same logon session. The scheduled task was configured as hidden and to run with SYSTEM privileges, making the activity worthy of investigation.

The observed command writes a test string to a file and is not independently proof of malicious execution. The source IP is taken from the test dataset and is not established as a malicious IOC.

## Limitations
- The local validation uses an explicit 60-second time-difference check.
- The generated Splunk SPL correlates events by Logon ID but does not enforce a strict 60-second sliding window or event order.
- No benign false-positive validation has been completed for this correlation rule.
- The sample demonstrates suspicious behavior, not confirmed malicious intent.

## Conclusion
The correlation logic successfully identified a network logon and scheduled task modification associated with the same user session. The result demonstrates the value of combining Windows Security events for contextual detection.
