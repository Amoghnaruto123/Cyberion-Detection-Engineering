# Benign Detection Testing

Date: 2026-11-03

## Baseline
- Source: Local Windows Sysmon telemetry
- Event ID: 10 (Process Access)
- Events collected: 1
- Source process: MicrosoftEdgeUpdate.exe
- Target process: lsass.exe
- Granted access: 0x1000
- Digital signature: Valid
- Signer: Microsoft Corporation

## Negative Test Results

| Detection Rule | Events Tested | Matches |
|---|---:|---:|
| Suspicious PowerShell Access to LSASS | 1 | 0 |
| Mimikatz Accessing LSASS | 1 | 0 |

## Assessment
The collected event did not match either detection rule.
The executable had a valid Microsoft digital signature.

This is an initial benign-event test, not a measured false-positive rate.
Additional benign telemetry is required for broader validation.

Rule 2 requires separate testing against Windows Security Event ID 4663.

Security Event ID 4663.

## Rule 2 - Benign Testing Limitation

- Required telemetry: Windows Security Event ID 4663
- Local Security log search: No matching events found
- Kernel Object auditing: Disabled
- File System auditing: Disabled
- Result: Local benign validation inconclusive

The rule was successfully tested against attack-oriented EVTX telemetry.
Local benign validation remains pending because the required Security auditing telemetry is unavailable.

No Windows audit policy changes were made.
