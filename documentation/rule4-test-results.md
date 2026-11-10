
# Rule 4 - Suspicious FTP-to-CMD Execution

- Rule: win_suspicious_ftp_cmd_execution
- MITRE ATT&CK: T1059.003 - Windows Command Shell
- Dataset: exec_sysmon_1_ftp.evtx
- Log source: Sysmon Event ID 1
- Events analyzed: 4
- Events matched: 1

## Matched Event
- Parent process: ftp.exe
- Child process: cmd.exe
- Command line: cmd.exe /C calc.exe
- User: IEWIN7\IEUser

## Assessment
The detection successfully identified a command shell process
spawned by the FTP client in the attack-oriented sample.

This is a positive test result. Benign testing and false-positive
tuning remain pending.
