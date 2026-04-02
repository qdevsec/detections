# Detection as a System

Raw Logs -->
pipeline.yml (normalize fields) -->
Structured Data -->
rule.yml (apply detection logic using IOCs + behavior) -->
Alert -->
SOC Response -->
Feedback --> Improve rule/pipeline

## 1. Log ingestion
Logs are generated and sent to a SIEM in an unformatted way

- Log sources and devices:
    - <u>Identity and Access Management (IAM):</u>
        - Active Directory (AD) / Domain Controllers:
            - user authentication (success/failed attempts)
            - account lockouts
            - privilege escalations
        - LDAP
        - SSH / Unix Authentication
            - /var/log/auth.log
            - /var/log/secure
        - SSO systems & MFA logs 
            - Okta 
            - Azure AD (Entra ID)
            - Duo Security
    - <u>Endpoints Detection & Response (EDR):</u>
        - EDR alerts
        - Sysmon (Windows) ()
        - auditd (Linux)
        - antivirus (AV) software
        - macOS security logs
        - Linux Systems (AuditD, syslog, file integrity monitoring logs)
    - <u>Network Infrastructure, security, perimeter devices:</u>
        - Firewalls (NGFW) (Connection, Traffic, Security)
            - Perimeter
            - Internal
            - Virtual firewalls
        - Web Application Firewalls (WAF)
            - Detecting attacks against web applications
        - VPN concentrators
        - Routers
        - Switches
        - IPS / IDS
        - Email Security Gateways
            - Phishing, malicious attachments (Microsoft 365, Mimecast)
        - Web Proxies & Secure Web Gateways (SWG)
            - Outbound web browsing data
            - Traffic analysis
        - NetFlow / IPFIX:
            - Network flow records from routers and switches
    - <u>Cloud Infrastructure:</u>
        - Cloud Provider Audit Logs
            - AWS CloudTrail / GuardDuty
            - Azure Activity Logs
            - Google Cloud Platform (GCP) Audit logs (API activity)
        - Cloud Storage & Data Stores:
            - AWS S3 access logs
            - Azure File Storage
        - SaaS Applications 
            - M365 logs
            - Slack / Teams (collaboration data)
            - Google Workspace
        - Container Logs (Kubernetes audit logs, Docker logs)
    - <u>Servers (Application, Web, Database) & Operating Systems:</u>
        - Windows Event Logs (System, Security, Application)
        - Linux syslog
        - Application Servers
        - Web Servers
        - Databases Servers
        - Authentication Logs
    - <u>Applications & Databases:</u>
        - SaaS platforms (Microsoft 365, Slack, Saleforces)
        - Database audit logs (SQL, NoSQL)
        - Web servers (Apache, IIS)
    - <u>Infrastructure Services:</u>
        - DNS logs (outbound traffic, DNS queries to malicious domains)
        - DHCP logs (IP address mapping to devices)
        - Database Audit logs (db user activity, queries, privilege change sql, nosql)
        - Web servers (apache, Nginx, IIS (HTTP/HTTPS logs))
    - <u>Vulnerability & Threat Intelligence</u>
        - Vulnerability Management Scanners
            - Nessus
            - Rapid7 (mapping assets)
        - Threat Intel Feeds
            - Indicators of Compromise (IoCs) integrated into SIEM
    
    - Other Sources include
        - Windows Event Logs (process creation, login events)
        - EDR telemetry
        - DNS logs 
        - Email gateways

# 2. Normalization & Enrichment

## Normalization
make sure all ingested data follows a consistent schema so "apples" to "apples" can be compared.

- <u>Parsing and Field Extraction:</u> SIEM uses regex or predefined parsing to identify and extract key data points from the raw log message
    - source IP
    - username
    - event ID

- <u>Field Mapping:</u> extracted fields are mapped to a standard taxonomy
    - An example is terms like `src`, `sip`, `client_ip` are renamed to single common field name like `source_ip`

- <u>Data Type Standardization:</u> values are converted into uniform formats
    - an example is are all IP address follow the same notation and all severity levels are mapped to a standard scale 
        - 1 - 5
        - Low to Critical

- <u>Timestamp Harmonization:</u> SIEMs convert varied time formats (Unix epoch, ISO 8601) to single synchronized UTC format so there is accurate event sequencing during correlation

- <u>Event Classification:</u> Similar activites from different vendors are assigned a standard category
    - for example `failed login` (windows), `denied access` (linux) --> `authentication_failure`  

## Enrichment
This steps adds additional context to the data has now been normalized so the `who`, `what` and `where` can be seen

- <u>Identity Context:</u> Logs may be combined with user directories (Microsoft Active Directory) to add details like the user's full name, department, job title, and manager

- <u>Asset Context:</u> IP addresses are connected to asset management systems (CMDBs) so that the device's role and device owner can be obtained
    - example `Critical Database Server` vs `Employee Laptop`

- <u>Threat Intelligence Integration:</u> Indicators of Compromise (IoCs) like IP addresses, file hashes or domains are automatically checked against 3rd party Threat Intelligence Feeds to flag malicious actors

    - Enrichment Types
        - Reputation Data:
            - Assigns risk scores to IPs, domains, and files
        - Threat Actor Attribution
            - Links activity to known groups
        - Malware / Tool Associations
            - Connects IoCs to malware families
        - Geolocation
            - Identifies region / country of activity
        - MITRE ATT&CK Mapping
            - Shows related TTPs
        - Temporal Data
            - Provides timelines of activity

- <u>Geolocation:</u> IP addresses are mapped to physical locations like `country`, `city` or `coordinates` to help detect suspicious "impossible travel" or logins from unauthorized regions

- <u>Vulnerabiilty Context:</u> Event data is cross-referenced with recent scan reports to determine if an attacked system is actually vulnerable to the specific exploit being attempted

Modern Security Data Pipelines acting as a pre-processing layer for SIEMs may use pipeline.yml helps to standardize. Normalization and enrichment tasks file formats can be .conf, xml, json, yaml, UI-builder.

Elastic Stack: 
- logstash uses pipelines.yml
- Elastic Agent / Beats

Splunk:
- props.conf
- transform.conf

Microsoft Sentinel
- KQL (kusto) / JSON

Google Chronicle
- Logstash-like syntax / CBN

IBM QRadar
- GUI-based / Regex

Wazuh
- XML

Exabeam
- GUI-based / JSON
 

Splunk uses CIM (Common Information Model) and conf files
- props.conf - defines rules, how to break line, what tranformations to apply
- transforms.conf - contains actual regular expression or mapping logic referred to by props.conf

sample pipeline.yml

```
name: windows_pipeline
transformations:
  - field: EventID
    target: event.code
  - field: Computer
    target: host.name
  - field: CommandLine
    target: process.command_line
```

## 3. Threat discovered

A zero day or a threat is discovered and the attacker runs
```
powershell.exe -EncodedCommand <base64>
```
## 4. IoCs (Indicators of Compromise) are Identified 

IoCs can be artifacts like strings, hashes, IPs
- in the example above it can be `powershell.exe` or `-EncodedCommand`
- There can also be low-level signals

## 5. Detection Designing
At this point the question asked is what is the behavior showing?

- The PowerShell executing encoded commands
- A rule can then be written based on <u>behavior</u>

## 6. The Detection Rule

Here is a sample rule following the incident

rule.yml

```
id: <value>
title: Suspicious PowerShell Encoded Command
description: Detects PowerShell execution with encoded commands
logsource:
  product: windows
detection:
  selection:
    process.name: "powershell.exe"
    process.command_line|contains: "EncodedCommand"
  condition: selection

level: high
tags:
  - attack.execution
  - attack.t1059
```

the two IoCs are the string based "EncodedCommand" and contextual indicator "powershell.exe"

<u>Combining</u> these two results in <u>behavioral detection</u>

## 7. Testing, Validating, Tuning, DaC (detection as code)

- The rule should be ran against historical log
    - can simulate the attack
        - look for false positive
        - missed detections

- May need to tune, rules may can authorized services running
    - for example, admin scripts also use encoded PowerShell

Refine, fiter example

```
filter:
  user.name: "admin_service_account"
condition: selection AND NOT filter
```

Complete tuned rule - rule.yml

```
id: <value>
title: Suspicious PowerShell Encoded Command
description: Detects PowerShell execution with encoded commands
logsource:
  product: windows
detection:
  selection:
    process.name: "powershell.exe"
    process.command_line|contains: "EncodedCommand"

#benign activity to exclude
filter:
  user.name: 
    - "admin_service_account"
    - "svc_admin"
    - "svc_sccm"
  host.name: "it-automation-server"
condition: selection AND NOT filter
  

level: high
tags:
  - attack.execution
  - attack.t1059
```

Filter Logic

FILTER triggers ONLY if:

Trust User(s) AND Trusted Host


So 

```
Alert if:
    (selection is true)
AND
    NOT (
        (user is admin_service_account OR svc_admin OR svc_sccm)
        AND
        (host is it-automation-server)
    )
```

Detection-as-Code (DaC)
- merge rule into a repo
- deploy via CI/CD to SIEm
- the UUID will make the rule unique

Now there will be alerting, results of alerting may be
- create ticket
- isolate host
- enrich with threat intel

Continous Improvement loop
- Analyst give feedback (alert is noisy)
- New attacker techniques arise
- Logs change


## TDE
- Design data pipelines
- Translates threat intel --> detections
- Balances false positives vs coverage
- Maintains detection-as-code repos
- Continously adapts to attacker behavior
