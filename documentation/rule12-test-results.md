# Rule 12 - Suspicious Service Configuration Launching Hidden PowerShell

- Rule: win_suspicious_service_hidden_powershell
- MITRE ATT&CK: T1569.002 - Service Execution
- Dataset: LM_sysmon_psexec_smb_meterpreter.evtx
- Log source: Sysmon Event ID 13
- Events matched: 1

## Matched Event

- Timestamp: 2019-05-01 01:56:51
- Source process: services.exe
- Registry path: HKLM\System\CurrentControlSet\services\hello\ImagePath
- Detection indicators: PowerShell, hidden window, -nop
- Result: Matched

## Assessment

The detection identified a Windows service ImagePath modification
configured to launch hidden PowerShell with suspicious execution options.

The rule successfully matched the attack-oriented EVTX sample.

This is a positive test result. Benign testing and false-positive
tuning remain pending.
