# Rule 7 - Suspicious Mshta Execution from Internet Cache

- Rule: win_suspicious_mshta_internet_cache
- MITRE ATT&CK: T1218.005 - Mshta
- Dataset: sysmon_mshta_sharpshooter_stageless_meterpreter.evtx
- Log source: Sysmon Event ID 1
- Events matched: 1

## Matched Event

- Process: mshta.exe
- Parent process: iexplore.exe
- HTA file: update.hta
- Execution path: Internet Explorer Temporary Internet Files
- User: IEWIN7\IEUser

## Assessment

The detection identified mshta.exe executing an HTA file from the Internet Explorer cache.

The rule successfully matched the attack-oriented EVTX sample.

This is a positive test result. Benign testing and false-positive tuning remain pending.
