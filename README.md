# \# Cyberion Detection Engineering \& Threat Hunting

# 

# A four-week, hands-on cybersecurity project focused on detection engineering, threat hunting, adversary behavior analysis, and incident response using real-world security telemetry.

# 

# The project follows a practical detection engineering workflow, from telemetry collection and threat research to Sigma rule development, detection validation, threat hunting, incident investigation, and response documentation.

# 

# \---

# 

# \## 1. Project Overview

# 

# Cyberion Detection Engineering focuses on identifying, analyzing, and investigating adversary behavior through Windows endpoint telemetry, security audit logs, network traffic, and web server logs.

# 

# The project aims to demonstrate practical skills in:

# 

# \- Security telemetry analysis

# \- Detection engineering and Sigma rule development

# \- MITRE ATT\&CK mapping

# \- Correlation-based detection

# \- Hypothesis-driven threat hunting

# \- Incident investigation and reporting

# \- IOC research and operationalization

# \- Incident response playbook development

# \- Detection validation and tuning

# 

# \## 2. Key Project Deliverables

# 

# | Deliverable | Results |

# |---|---|

# | Standalone Sigma Detection Rules | 12 |

# | Correlation Detection Rules | 3 |

# | Total Detection Rules | 15 |

# | ATT\&CK Techniques Documented | 26 |

# | ATT\&CK Tactics Represented | 9 |

# | Threat Hunting Investigations | 2 |

# | Incident Investigation Reports | 2 |

# | Incident Response Playbooks | 3 |

# | Detection Tuning Exercises | 3 |

# | Telemetry Categories | 4 |

# | IOC Research Register | 1 |

# 

# \## 3. Telemetry Sources

# 

# Four telemetry categories were selected and analyzed.

# 

# | Telemetry Source | Purpose |

# |---|---|

# | Sysmon | Process creation, process access, registry modifications, and network connections |

# | Windows Security Logs | Authentication activity, account creation, group membership changes, and scheduled task events |

# | PCAP | Network traffic analysis, DNS activity, and suspected command-and-control communication |

# | IIS Logs | HTTP request analysis and investigation of HTTP-based RDP tunnelling |

# 

# \### Dataset

# 

# The primary endpoint dataset was sourced from:

# 

# \[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

# 

# Additional network and web telemetry included selected PCAP and IIS log samples.

# 

# Processed telemetry and analysis outputs are maintained in the `datasets/processed/` directory.

# 

# \## 4. Detection Engineering

# 

# A total of 15 detection rules were developed and tested against selected attack telemetry.

# 

# \### Standalone Detection Rules

# 

# | No. | Detection Rule | Category | MITRE ATT\&CK |

# |---|---|---|---|

# | 1 | Suspicious PowerShell LSASS Access | Credential Access | T1003.001 |

# | 2 | Windows Security LSASS Memory Read | Credential Access | T1003 |

# | 3 | Mimikatz LSASS Access | Credential Access | T1003.001 |

# | 4 | Suspicious FTP Command Execution | Execution | T1059.003 |

# | 5 | Suspicious Rundll32 File Protocol Execution | Defense Evasion | T1218.011 |

# | 6 | Renamed Regsvr32 Remote Scriptlet Execution | Defense Evasion | T1218.010 |

# | 7 | Suspicious Mshta Execution from Internet Cache | Defense Evasion | T1218.005 |

# | 8 | Suspicious Windows Run Key Modification | Persistence | T1547.001 |

# | 9 | Startup Folder Registry Modification | Persistence | T1547.001 |

# | 10 | Suspicious Local Administrator Group Addition | Persistence | Account and group manipulation activity |

# | 11 | Hidden Local Account Creation | Persistence | T1136.001 |

# | 12 | Hidden PowerShell Execution Through Service Configuration | Execution | T1569.002 |

# 

# \### Correlation Detection Rules

# 

# Three correlation-style detection rules were developed:

# 

# 1\. \*\*Hidden PowerShell Service Execution:\*\* Correlates suspicious service registry modification with subsequent process creation using ProcessGuid.

# 2\. \*\*Mshta Network Connection:\*\* Correlates Mshta execution with a related network connection using ProcessGuid.

# 3\. \*\*Logon and Scheduled Task Modification:\*\* Correlates a network logon event with scheduled task modification using the same Logon ID.

# 

# The rules include detection conditions, MITRE ATT\&CK mappings, severity rationale, false-positive considerations, and supporting test evidence.

# 

# \## 5. MITRE ATT\&CK Coverage

# 

# The coverage matrix documents 26 techniques and sub-techniques across 9 tactics.

# 

# The tactics represented are:

# 

# \- Initial Access

# \- Execution

# \- Persistence

# \- Defense Evasion

# \- Credential Access

# \- Discovery

# \- Lateral Movement

# \- Command and Control

# \- Exfiltration

# 

# Coverage is classified into four categories:

# 

# \- \*\*Implemented:\*\* A standalone detection rule has been created and tested against attack telemetry.

# \- \*\*Correlation:\*\* A correlation rule has been created and tested against attack telemetry.

# \- \*\*Hunt Candidate:\*\* A technique identified for further investigation through threat hunting.

# \- \*\*Planned:\*\* A technique identified as a future detection opportunity.

# 

# Refer to:

# 

# `mitre-coverage/mitre-attack-coverage-matrix.md`

# 

# \## 6. Threat Hunting Investigations

# 

# Two hypothesis-driven threat hunting investigations were conducted.

# 

# \### Hunt 1: DNS Tunnelling

# 

# Investigated suspicious DNS TXT record activity and potential command-and-control communication.

# 

# Analysis included:

# 

# \- DNS query patterns and repeated TXT record requests.

# \- Encoded PowerShell content within DNS TXT responses.

# \- Communication between internal hosts.

# \- Evidence of script retrieval through DNS TXT records.

# \- Indicators associated with DNS-based command-and-control activity.

# 

# \### Hunt 2: HTTP-Based RDP Tunnelling

# 

# Investigated suspicious HTTP requests associated with the Tunna tunnelling tool.

# 

# Analysis included:

# 

# \- Repeated HTTP GET and POST requests.

# \- Suspicious HTTP endpoint activity.

# \- RDP port 3389 tunnelling parameters.

# \- Client and web server communication.

# \- Evidence limitations concerning successful RDP session establishment.

# 

# Detailed findings are available in the `documentation/` directory.

# 

# \## 7. Incident Investigations

# 

# Two incident reports were developed.

# 

# \### Case 001: LSASS Credential Access

# 

# Investigated suspicious process access to the Local Security Authority Subsystem Service (LSASS), including evidence associated with credential dumping activity.

# 

# The investigation focuses on process access telemetry, suspicious memory access, attack behavior, and recommended response actions.

# 

# \### Case 002: HTTP-Based RDP Tunnelling

# 

# Investigated HTTP activity associated with the Tunna tunnelling tool and its use of HTTP requests to proxy RDP traffic.

# 

# The investigation examines HTTP request patterns, tunnelling parameters, network evidence, and associated security implications.

# 

# The incident reports document available evidence, activity timelines, MITRE ATT\&CK mappings, impact considerations, and recommended response actions.

# 

# Refer to `incident-reports/`.

# 

# \## 8. Incident Response Playbooks

# 

# Three incident response playbooks were created:

# 

# 1\. \*\*LSASS Credential Dumping Response\*\*

# 2\. \*\*DNS Tunnelling Investigation and Response\*\*

# 3\. \*\*HTTP-Based RDP Tunnelling Investigation and Response\*\*

# 

# The playbooks provide guidance for:

# 

# \- Incident identification and triggering conditions.

# \- Investigation and evidence collection.

# \- Containment recommendations.

# \- Eradication and recovery considerations.

# \- Stakeholder communication.

# 

# Refer to `playbooks/`.

# 

# \## 9. IOC Research

# 

# An IOC register was developed to document relevant indicators identified during telemetry analysis and threat research.

# 

# The register includes available indicator details, associated activity, investigation context, and recommended operational handling.

# 

# Refer to:

# 

# `ioc-research/ioc-register.md`

# 

# \## 10. Detection Validation and Tuning

# 

# Detection rules were tested against selected attack telemetry from the project datasets.

# 

# Validation activities included:

# 

# \- Testing standalone detection logic against relevant EVTX samples.

# \- Testing correlation logic against related event sequences.

# \- Reviewing available benign local telemetry.

# \- Creating controlled synthetic benign events for three tuning exercises.

# \- Evaluating detection exclusions and their impact on attack detection.

# 

# \### Detection Tuning Exercises

# 

# Three detection rules underwent controlled tuning:

# 

# 1\. PowerShell LSASS Access Detection

# 2\. Rundll32 File Protocol Detection

# 3\. Renamed Regsvr32 Remote Scriptlet Detection

# 

# Synthetic benign events were explicitly labelled and used to simulate false-positive scenarios. They are not production false-positive observations.

# 

# Some rules could not receive complete benign validation because suitable local telemetry was unavailable.

# 

# The illustrative allowlist paths used during tuning must be verified against trusted applications before any production deployment.

# 

# Detailed tuning reports are available in:

# 

# `documentation/tuning-tests/`

# 

# \## 11. Technology Stack

# 

# | Technology | Usage |

# |---|---|

# | Python | Telemetry processing and detection testing |

# | Pandas | Structured event analysis |

# | NumPy | Data processing |

# | dpkt | PCAP parsing and network traffic analysis |

# | Sigma CLI | Detection rule development and validation checks |

# | Splunk SPL | Search and correlation logic |

# | Sysmon | Windows endpoint telemetry |

# | Windows Event Logs | Security and system activity analysis |

# | MITRE ATT\&CK | Adversary technique mapping |

# | PowerShell | Windows telemetry collection and analysis |

# | Git and GitHub | Version control and project management |

# 

# \## 12. Repository Structure

# 

# ```text

# Cyberion-Detection-Engineering/

# │

# ├── datasets/

# │   ├── raw/

# │   └── processed/

# │

# ├── detections/

# │   ├── execution/

# │   ├── credential\_access/

# │   ├── persistence/

# │   ├── lateral\_movement/

# │   ├── command\_and\_control/

# │   └── correlation/

# │

# ├── documentation/

# │   └── tuning-tests/

# │

# ├── incident-reports/

# │

# ├── ioc-research/

# │

# ├── mitre-coverage/

# │

# ├── notebooks/

# │

# ├── playbooks/

# │

# ├── presentation/

# │

# ├── README.md

# │

# └── .gitignore

# ```

# 

# \## 13. Project Methodology

# 

# The project followed a structured four-week workflow.

# 

# | Phase | Activities |

# |---|---|

# | Week 1 | Telemetry selection, dataset preparation, data dictionary, and ATT\&CK research |

# | Week 2 | Detection engineering, Sigma rule development, and initial testing |

# | Week 3 | Threat hunting, network analysis, and incident investigations |

# | Week 4 | Correlation detections, tuning, playbooks, documentation, and final presentation |

# 

# \## 14. Validation and Limitations

# 

# \- Testing was performed using selected public attack telemetry rather than a production enterprise environment.

# \- Benign validation was limited by the availability of suitable local events.

# \- Synthetic benign events were used for controlled tuning exercises.

# \- Correlation implementations have documented temporal-ordering and time-window limitations.

# \- Some detection rules could not receive complete benign validation.

# \- The project does not represent a production SIEM deployment or automated SOAR platform.

# \- Detection coverage is limited to the techniques documented in the ATT\&CK coverage matrix.

# 

# These limitations are documented to distinguish tested results from assumptions and future improvements.

# 

# \## 15. Project Documentation

# 

# | Directory | Contents |

# |---|---|

# | `detections/` | Standalone Sigma and correlation detection rules |

# | `datasets/` | Raw and processed telemetry |

# | `documentation/` | Methodology, data dictionary, test results, threat hunts, and tuning reports |

# | `incident-reports/` | Detailed incident investigation reports |

# | `ioc-research/` | IOC research register |

# | `mitre-coverage/` | MITRE ATT\&CK coverage matrix |

# | `playbooks/` | Incident response playbooks |

# | `presentation/` | Final project presentation |

# 

# Additional documentation:

# 

# \- `documentation/methodology.md`

# \- `documentation/executive-summary.md`

# 

# \## 16. Project Status

# 

# \*\*Completed — Detection Engineering, Threat Hunting, and Incident Response Documentation\*\*

# 

# \*\*Project Duration:\*\* 4 Weeks

# 

# This project demonstrates practical experience in security telemetry analysis, detection engineering, Sigma rule development, MITRE ATT\&CK mapping, threat hunting, incident investigation, IOC research, and detection tuning.

# 

# \---

# 

# \*\*Disclaimer:\*\* This project is intended for cybersecurity education, research, and portfolio demonstration. Attack telemetry was analyzed for defensive security purposes.

