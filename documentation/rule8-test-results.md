# Rule 8 - Suspicious Windows Run Key Persistence

- Rule: win_suspicious_run_key_executable
- MITRE ATT&CK: T1547.001 - Registry Run Keys / Startup Folder
- Dataset: evasion_persis_hidden_run_keyvalue_sysmon_13.evtx
- Log source: Sysmon Event ID 13
- Events matched: 1

## Matched Event

- Process: a.exe
- Process ID: 3728
- Registry key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
- Configured executable: C:\Windows\Tasks\taskhost.exe
- User: Not populated in the source event

## Assessment

The detection identified an executable configured in the machine-wide Windows Run registry key, indicating a potential persistence mechanism.

The rule successfully matched the attack-oriented EVTX sample.

This is a positive test result. Benign testing and false-positive tuning remain pending.
