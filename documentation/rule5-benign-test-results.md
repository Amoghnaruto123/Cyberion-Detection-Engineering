# Rule 5 - Benign Test Results

## Detection
Suspicious Rundll32 File Protocol Handler

## Test Source
Local Windows Sysmon Operational log (Event ID 1).

## Results
- Benign events examined: 2
- Detection matches: 0
- Expected result: No alerts
- Observed result: No alerts

## Observed Activity
1. rundll32.exe executing shell32.dll,SHCreateLocalServerRunDll, launched by svchost.exe.
2. rundll32.exe executing PcaSvc.dll,PcaPatchSdbTask, launched by svchost.exe.

Neither event contained the targeted url.dll FileProtocolHandler and file:// indicators.

## Conclusion
The detection correctly ignored both observed benign executions. This is an initial benign validation and does not establish a statistically representative false-positive rate.

## Limitation
Validation is based on two locally observed events only.
