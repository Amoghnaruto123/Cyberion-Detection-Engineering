# Project Methodology – Cyberion Detection Engineering & Threat Hunting

## 1. Project Approach

This project follows a practical detection engineering and threat hunting methodology focused on identifying, analysing, validating and documenting suspicious activity across endpoint, network and web-server telemetry.

The work was conducted in stages: telemetry acquisition, data analysis, detection development, attack telemetry validation, threat hunting, incident reporting and detection tuning.

## 2. Telemetry Collection and Selection

The project used multiple telemetry sources to investigate different categories of adversary behaviour.

| Telemetry source | Purpose |
|---|---|
| Windows Sysmon logs | Process creation, process access, network connections and registry modifications |
| Windows Security logs | Authentication, object access and local group changes |
| PCAP network captures | DNS communication and potential command-and-control activity |
| IIS web-server logs | HTTP request patterns and potential tunnelling activity |

EVTX attack samples were obtained from the EVTX-ATTACK-SAMPLES repository. Selected PCAP and IIS log samples were also analysed.

The telemetry data dictionary documents the relevant event fields, their meanings and their detection use cases.

## 3. Data Analysis

EVTX files were examined to identify relevant event IDs, process relationships, registry modifications, authentication activity and suspicious command-line arguments.

Network traffic was analysed using Python and the dpkt library. DNS queries and responses were examined for unusual patterns, including repeated TXT-record communication and encoded payload characteristics.

IIS logs were reviewed for repeated HTTP requests, suspicious query parameters and activity associated with tunnelling tools.

Extracted event data was organised into CSV files where appropriate to support repeatable analysis and detection testing.

## 4. Detection Engineering

Detection rules were developed using Sigma YAML format and mapped to relevant MITRE ATT&CK techniques.

The detection development process included:

1. Identifying suspicious behaviour from attack telemetry.
2. Selecting the relevant event source and event fields.
3. Defining detection conditions and matching logic.
4. Mapping the behaviour to MITRE ATT&CK.
5. Assigning severity based on potential impact and observed behaviour.
6. Documenting expected false positives and investigation considerations.
7. Creating corresponding SPL queries where applicable.

The project contains 12 standalone detection rules and 3 correlation-style rules.

The correlation rules combine related events using attributes such as Process GUID and Logon ID, with defined time windows.

## 5. Detection Validation

Rules were tested against selected attack telemetry from the EVTX dataset.

Validation involved extracting relevant events, applying the detection conditions and comparing expected matches with actual results.

Controlled benign scenarios were also created for selected rules to examine potential false-positive behaviour.

Three detection rules underwent a tuning exercise. The tuning process introduced exclusions for simulated approved software activity, then retested the original attack evidence to check whether the intended detections remained effective.

**Validation limitation:** The synthetic benign scenarios are controlled test cases, not false positives observed in production. The tuned-rule comparisons used PowerShell logic equivalent to the Sigma conditions rather than end-to-end Sigma backend execution. Full production validation and verification of the illustrative allowlist paths remain necessary.

## 6. Threat Hunting

Two hypothesis-driven hunts were conducted:

- DNS tunnelling: Investigated unusual DNS TXT-record activity, repeated queries and encoded command retrieval.
- HTTP-based RDP tunnelling: Investigated repeated HTTP requests associated with the Tunna tunnelling tool and parameters referencing TCP port 3389.

Each hunt documented its hypothesis, telemetry examined, observations, investigation findings and limitations.

## 7. Incident Analysis and Reporting

Two incident reports were prepared from the analysed telemetry:

- LSASS credential-access activity.
- HTTP-based RDP tunnelling activity.

The reports document the relevant entities, activity timeline, attack indicators, MITRE ATT&CK mapping, impact considerations, investigation findings and recommended response actions.

Three incident response playbooks were developed to provide structured investigation, containment, eradication, recovery and communication guidance.

## 8. MITRE ATT&CK Mapping and IOC Research

Detection rules and investigated behaviours were mapped to relevant MITRE ATT&CK techniques.

The coverage matrix provides a consolidated view of technique coverage across the documented detection work.

An IOC register was also prepared to document indicators identified during the investigations, their context and their operational relevance.

## 9. Tools and Technologies

- Sigma: Detection rule authoring.
- Splunk SPL: Search-query representation of detection logic.
- Python: Telemetry parsing and analysis.
- dpkt: PCAP packet analysis.
- PowerShell: Windows event-log investigation and validation.
- Sysmon: Endpoint telemetry.
- MITRE ATT&CK: Adversary behaviour classification.
- Git: Version control and project management.

## 10. Limitations

- Testing was conducted using selected public attack datasets and controlled benign scenarios, not a production enterprise environment.
- Some rules lack suitable benign telemetry for meaningful false-positive validation.
- Synthetic tuning scenarios do not establish that an exclusion is safe for production deployment.
- Correlation logic was evaluated against selected attack samples; documented SPL time-bucket limitations should be considered during deployment.
- Sigma YAML parsing and essential-field checks were performed, but full Sigma backend validation was not established through the installed CLI.
- Findings are limited to the telemetry available in the selected samples.

## 11. Methodology Outcome

This methodology produced a documented detection engineering and threat hunting project consisting of standalone and correlation-style rules, telemetry analysis, validation evidence, threat hunts, incident reports, response playbooks, IOC research and MITRE ATT&CK coverage documentation.
