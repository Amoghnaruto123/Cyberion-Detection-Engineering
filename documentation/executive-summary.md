# Executive Summary
## Cyberion – Detection Engineering & Threat Hunting

## 1. Project Overview

Cyberion Detection Engineering & Threat Hunting is a practical cybersecurity project focused on developing, testing and documenting detection capabilities across endpoint, network and web-server telemetry.

The project applies detection engineering and threat hunting methodologies to identify suspicious activity, map adversary behaviour to MITRE ATT&CK and develop actionable incident response guidance.

## 2. Project Objectives

- Analyse multiple telemetry sources to identify suspicious behaviour.
- Develop Sigma-based detection rules and corresponding SPL queries.
- Map detections and investigated behaviours to MITRE ATT&CK.
- Validate detection logic against attack telemetry.
- Conduct hypothesis-driven threat hunts.
- Document investigated incidents and recommended response actions.
- Research indicators of compromise and develop response playbooks.
- Improve detection quality through controlled tuning exercises.

## 3. Telemetry Sources

The project examined four telemetry categories:

| Source | Investigation focus |
|---|---|
| Windows Sysmon | Process execution, LSASS access, network connections and registry modifications |
| Windows Security | Authentication, object access and account/group activity |
| Network PCAP | DNS TXT-record communication and potential command-and-control |
| IIS logs | HTTP tunnelling activity and suspicious requests |

Attack telemetry was obtained primarily from EVTX-ATTACK-SAMPLES, alongside selected PCAP and IIS log samples.

## 4. Detection Engineering Results

A total of 15 detection rules were developed:

- 12 standalone Sigma detection rules.
- 3 correlation-style detection rules.

The detections cover behaviours including credential access, suspicious execution, persistence, service-based execution and related activity.

Each rule includes detection logic, MITRE ATT&CK mapping, severity considerations and false-positive documentation.

Attack telemetry was used to validate the detection logic. Three selected rules also underwent controlled tuning exercises using synthetic benign scenarios.

## 5. Threat Hunting Results

Two hypothesis-driven investigations were documented:

**DNS Tunnelling**

Analysis identified repeated DNS TXT-record communication, encoded content and PowerShell script retrieval behaviour. The findings were consistent with DNS-based command-and-control activity in the analysed sample.

**HTTP-Based RDP Tunnelling**

Analysis of IIS logs identified repeated HTTP GET and POST requests to an endpoint associated with the Tunna tunnelling tool. The request parameters referenced TCP port 3389, indicating an attempted or configured RDP tunnelling mechanism.

## 6. Incident Investigation

Two incident reports were prepared:

1. LSASS credential-access activity involving suspicious process access to the Local Security Authority process.
2. HTTP-based RDP tunnelling activity identified through IIS telemetry.

The investigations document relevant evidence, activity timelines, attack indicators, MITRE ATT&CK mappings, impact considerations and recommended response actions.

## 7. Detection Tuning

Three detection rules underwent controlled tuning exercises:

- PowerShell LSASS access.
- Rundll32 file-protocol execution.
- Renamed Regsvr32 remote scriptlet execution.

Synthetic benign scenarios were used to evaluate potential false-positive behaviour. Exclusions were introduced and the original attack evidence was retested to ensure the intended detections remained active.

These tests demonstrate controlled tuning behaviour, not production false-positive reduction. The illustrative allowlist paths require verification before operational deployment.

## 8. Supporting Deliverables

The project includes:

- 15 Sigma detection rules and corresponding SPL queries.
- Telemetry data dictionary and source analysis.
- Individual detection test reports.
- Three correlation-rule test reports.
- Three detection tuning reports and synthetic test fixtures.
- MITRE ATT&CK coverage matrix.
- Two threat hunting reports.
- Two incident investigation reports.
- IOC research register.
- Three incident response playbooks.
- Project methodology documentation.

## 9. Key Limitations

The project was conducted using selected public attack datasets and controlled test scenarios rather than a production enterprise environment.

Some rules did not have sufficient benign telemetry for meaningful false-positive validation. Synthetic tuning scenarios were used for selected rules and are explicitly identified as such.

Sigma YAML parsing and essential-field checks were performed, but full backend validation was not established through the installed Sigma CLI. Correlation logic and SPL implementations also have documented time-window limitations.

## 10. Conclusion

The Cyberion project demonstrates a practical detection engineering and threat hunting workflow, from telemetry analysis and rule development to validation, investigation, tuning and incident response documentation.

It establishes a foundation for further development, including broader benign telemetry validation, additional data-source coverage, production-grade correlation testing and deployment within an enterprise SIEM environment.
