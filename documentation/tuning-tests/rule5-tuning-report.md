# Rule 5 – Rundll32 File Protocol Handler Tuning

Date: 2026-11-10
Rule: Suspicious Rundll32 File Protocol Handler Execution
MITRE ATT&CK: T1218.011 – Rundll32

## 1. Tuning objective
Reduce alerts from an explicitly approved document viewer opening local documents.

## 2. False-positive test scenario
A synthetic benign event represented an approved document viewer launching Rundll32 to open a local HTML manual.

ParentImage: C:\Program Files\Contoso\DocumentViewer\viewer.exe
Image: C:\Windows\System32\rundll32.exe
CommandLine: rundll32.exe url.dll,FileProtocolHandler file://C:\ProgramData\Contoso\manual.html

This is simulated test data, not an observed production false positive.

## 3. Original detection result
The original detection logic matched the synthetic event: 1 match.

## 4. Tuning modification
Added an exclusion for ParentImage beginning with:
C:\Program Files\Contoso\DocumentViewer\

## 5. Retesting results

| Test | Original | Tuned |
|---|---:|---:|
| Synthetic benign document viewer event | 1 match | 0 matches |
| Original Rundll32 attack event 1 | 1 match | 1 match |
| Original Rundll32 attack event 2 | 1 match | 1 match |

The two attack events used cmd.exe as their parent and contained url.dll,FileProtocolHandler and file:// indicators.

## 6. Trade-off
Rundll32 executions launched by the approved viewer are excluded. If that application is compromised, malicious activity launched through it could be missed. The exception must be restricted to a verified application and controlled installation path.

## 7. Conclusion
The synthetic benign scenario was excluded while both original attack events remained detectable.

Validation used extracted CSV evidence and PowerShell logic equivalent to the Sigma conditions; this was not an end-to-end Sigma backend test.
