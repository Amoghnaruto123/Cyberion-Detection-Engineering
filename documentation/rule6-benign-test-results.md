# Rule 6 - Benign Test Results

## Detection
Renamed Regsvr32 Remote Scriptlet

## Test Source
Local Windows Sysmon Operational log (Event ID 1).

## Results
- Benign events examined: 3
- Detection matches: 0
- Expected result: No alerts
- Observed result: No alerts

## Observed Activity
Three regsvr32.exe process creation events associated with WPS Office.
- Executable: C:\Windows\System32\regsvr32.exe
- Parent process: ksomisc.exe
- Command: /s registering pdfwspv.dll
- DLL location: WPS Office application data directory.

## Conclusion
The three observed events did not match the detection conditions for renamed regsvr32 remote scriptlet execution.

## Limitation
Validation is based on three locally observed events only. This does not establish a statistically representative false-positive rate.
