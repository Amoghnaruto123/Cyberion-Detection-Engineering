# Correlation Rule 1 - Test Results

## Rule
Service Modification Followed by Hidden PowerShell Execution

## MITRE ATT&CK
- Technique: T1569.002
- Name: Service Execution
- Tactic: Execution

## Dataset
EVTX-ATTACK-SAMPLES

Sample:
LM_sysmon_psexec_smb_meterpreter.evtx

## Detection Components
- Event ID 13: Suspicious service ImagePath registry modification.
- Event ID 1: cmd.exe launched by services.exe with hidden PowerShell arguments.

## Test Results
- Registry event found: PASS
- Process creation event found: PASS
- Process GUID correlation: PASS
- Time difference: 0.015 seconds
- Correlation window: 30 seconds
- Within correlation window: PASS
- Overall correlation: PASS

## Correlation Evidence
Both events shared the following process GUID:

{365abb72-2586-5cc9-0000-0010dc530000}

The registry modification and process creation events were approximately
15 milliseconds apart.

## Splunk Conversion
- Sigma conversion: SUCCESS
- Output: mr_service_hidden_powershell.spl
- Correlation type: temporal
- Shared GUID alias: service_process_guid

## Limitations
The Splunk temporal correlation groups events into 30-second time buckets
and does not enforce event order. The original temporal_ordered correlation
was not supported by the Splunk backend.

This test validates the correlation logic against the selected EVTX sample.
It does not establish benign false-positive performance or prove that the
payload executed successfully on the analyst's machine.
