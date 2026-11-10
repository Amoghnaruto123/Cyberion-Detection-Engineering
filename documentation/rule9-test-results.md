# Rule 9 - User Startup Folder Registry Modification

- Rule: win_user_startup_folder_registry_modification
- MITRE ATT&CK: T1547.001 - Registry Run Keys / Startup Folder
- Dataset: persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.evtx
- Log source: Sysmon Event ID 13
- Events matched: 1

## Matched Event

- Process: reg.exe
- Process ID: 1520
- Registry value: User Shell Folders\startup
- Modified startup path: C:\ProgramData\StartupNewHomeAddress
- User: Not populated in the source event

## Assessment

The detection identified a modification to the Windows User Shell Folders Startup registry value, redirecting the Startup folder to a different location.

The rule successfully matched the attack-oriented EVTX sample.

This is a positive test result. Benign testing and false-positive tuning remain pending.
