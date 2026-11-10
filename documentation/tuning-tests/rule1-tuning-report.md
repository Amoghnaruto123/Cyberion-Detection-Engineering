# Rule 1 – PowerShell LSASS Access Tuning

Date: 2026-11-10
Rule: Suspicious PowerShell Access to LSASS
MITRE ATT&CK: T1003 – OS Credential Dumping

## 1. Tuning objective
Reduce alerts from an explicitly approved diagnostic path while retaining detection of suspicious PowerShell access to LSASS.

## 2. False-positive test scenario
A synthetic benign event was created representing approved diagnostic activity.

SourceImage: C:\Program Files\Contoso\Diagnostics\powershell.exe
TargetImage: C:\Windows\System32\lsass.exe
GrantedAccess: 0x1010
EventID: 10

This is simulated test data, not an observed production false positive.

## 3. Original detection result
The original detection logic matched the synthetic event: 1 match.

## 4. Tuning modification
Added an exclusion for SourceImage beginning with:
C:\Program Files\Contoso\Diagnostics\

## 5. Retesting results

| Test | Original | Tuned |
|---|---:|---:|
| Synthetic benign diagnostic event | 1 match | 0 matches |
| Actual PowerShell LSASS attack events | 2 matches | 2 matches |

The attack validation used two events from lsass_access_events.csv. Both had EventID 10, PowerShell as SourceImage, LSASS as TargetImage and GrantedAccess 0x1010.

## 6. Trade-off
The path exclusion reduces noise from the approved diagnostic location. However, a compromised or abused executable operating from that path could evade this specific detection. The exception must only be used for a genuinely controlled and trusted location.

## 7. Conclusion
The synthetic benign scenario was successfully excluded, while both original PowerShell LSASS attack events remained detectable.

Validation was performed against extracted CSV evidence using PowerShell logic equivalent to the Sigma conditions; this was not an end-to-end Sigma backend test.
