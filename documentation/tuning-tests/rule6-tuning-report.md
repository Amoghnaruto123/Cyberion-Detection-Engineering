# Rule 6 – Renamed Regsvr32 Tuning

Date: 2026-11-10
Rule: Renamed Regsvr32 Executing Remote Scriptlet
MITRE ATT&CK: T1218.010 – Regsvr32

## 1. Tuning objective
Reduce alerts from an explicitly approved internal software deployment agent.

## 2. Benign test scenario
A synthetic event represented an approved deployment utility registering an internal DLL through a renamed registration executable.

Image: C:\ProgramData\Contoso\Deployment\reghelper.exe
ParentImage: C:\Program Files\Contoso\DeploymentAgent\deploy.exe
Description: Microsoft(C) Register Server
CommandLine: reghelper.exe /i:http://deployment.contoso.example/components/approved.dll

This is simulated test data, not an observed production false positive.

## 3. Original detection result
The original detection logic matched the synthetic event: 1 match.

## 4. Tuning modification
Added an exclusion for ParentImage beginning with:
C:\Program Files\Contoso\DeploymentAgent\

## 5. Retesting results

| Test | Original | Tuned |
|---|---:|---:|
| Synthetic benign deployment event | 1 match | 0 matches |
| Original jabber.exe attack event | 1 match | 1 match |

The original attack evidence contained a renamed executable, Microsoft(C) Register Server description, remote HTTP scriptlet URL and DLL argument. Its parent was cmd.exe.

## 6. Trade-off
Executions launched by the approved deployment agent are excluded. If the agent is compromised, malicious activity launched through it could be missed. The exception must be restricted to a verified deployment installation.

## 7. Conclusion
The synthetic benign scenario was excluded while the original renamed Regsvr32 attack event remained detectable.

Validation used extracted CSV evidence and PowerShell logic equivalent to the Sigma conditions; this was not an end-to-end Sigma backend test.
