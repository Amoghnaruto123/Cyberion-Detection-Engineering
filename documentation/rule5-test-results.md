# Rule 5 - Suspicious Rundll32 File Protocol Handler Execution

- Rule: win_suspicious_rundll32_fileprotocol
- MITRE ATT&CK: T1218.011 - Rundll32
- Dataset: exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx
- Log source: Sysmon Event ID 1
- Events analyzed: 5 Rundll32 process-creation events
- Events matched: 2

## Matched Events

| Parent Process | Process | Command |
|---|---|---|
| cmd.exe | rundll32.exe | url.dll,FileProtocolHandler file:///C:/programdata/calc.hta |
| cmd.exe | rundll32.exe | url.dll,FileProtocolHandler file://C:/Windows/system32/calc.exe |

## Assessment

The detection identified two Rundll32 executions using url.dll,FileProtocolHandler to open local files.

The remaining Rundll32 executions used different invocation patterns, including OpenURL, and did not match this rule.

This is a positive test against attack-oriented telemetry. Benign testing and false-positive tuning remain pending.
