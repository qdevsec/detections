# Detection as a System

Raw Logs -->
pipeline.yml (normalize fields) -->
Structured Data -->
rule.yml (apply detection logic using IOCs + behavior) -->
Alert -->
SOC Response -->
Feedback --> Improve rule/pipeline


Building detection coverage across the kill chain

Initial Access -> C2 -> execution -> Payload Delivery

Ensure
- multiple detections per technique
- multiple techniques per tactic
- correlation across stages

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
        - SaaS platforms (Microsoft 365, Slack, Saleforce)
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

#### Ways logs can be sent

> Agents are push-base, reliable collectors installed close to the data source

> Method--------------------|--------Best for
>------------------------------------------------------------

> Agents(Forwarders/Beat)  --|--  Servers, endpoints, reliability

> Syslog  --|-- Network devices, Linux

> APIs --|-- Cloud & SaaS

> HTTP (HEC) --|-- Custom apps, microservices

> Kafka / streaming --|-- High-scale pipelines

```
[Endpoints] --UF--> [Heavy Forwarder] --> [Indexers] --> [Search head]
[Network Devices] --Syslog--> [Syslog Server] --HF--> [Search head]
```

##### Syslog 

- Syslog server
    - Receives log messages from multiple devices
    - Stores or forwards them
    - Sometimes parses or filters them before sending to a SIEM like Splunk Enterprise or Elastic Stack
    - It uses the Syslog protocol which is a standard for message logging across systems
    - Device -> Syslog Server -> SIEM

    - Syslog server acts as a collector + relay layer

###### Simple flow
1. Device generates a log:

```
Failed login from 192.168.1.10
```
2. Sends that message over the network using Syslog:
    - UDP (fast, but unreliable)
    - TCP (reliable)
    - TLS (secure syslog)

3. The syslog server:
    - Receives the message 
    - Optionally writes it to disk
    - Forwards it to your SIEM

###### Common Syslog sources

- These usually dont support agents, so syslog is the default:
    - Firewalls (Palo Alto, Cisco ASA)
    - Routers & switches
    - Linux / Unix systems
    - IDS / IPS tools
    - Load balancers
- That's why syslog is still essential

###### Popular syslog server

- Some widely used ones:
    - rsyslog (very common on linux)
    - syslog-ng
    - Graylog (more full-featured)

###### Benefits of Syslog server

A siem, for example Splunk can act as a syslog receiver, organizations often use a dedicated syslog server

1. Centralization
- devices send logs to one place

2. Decoupling
- Devices don't need to know about your SIEM

Change SIEM -> no need to reconfigure 500+ devices

3. Buffering & reliability
- Prevents data loss if SIEM is down
- Can queue logs

4. Filtering & routing
Can:
    
- Drop noisy logs
- Route logs to different destinations

5. Security zone bridging
```
DMZ devices -> Syslog server in DMZ -> Internal SIEM
```
###### Disadvantages of Syslog server
- UDP can lose logs
- No built-in structure (security?) (mostly plain text)
- Limited metadata compared to modern formats (JSON)
- Weak authentication unless using TLS


#### Methods
- 1. Agent-Based Collection (robust, controlled)
    - Splunk: Universal forwarder / Heavy forwarder
    - Elastic: Beats (filebeat, winlogbeat) or elastic agent

    - Benefits of agents:
        - Reliable delivery (buffering, retry)
        - Secure transport (TLS)
        - Local filtering / processing
        - Works well for endpoints (servers, VMs)

- 2. Agentless Collection
    - a) Syslog (huge in networking)
        - Devices (routers, firewalls, switches) send logs directly
        - Uses UDP / TCP (port 514)
        - Examples:
            - Firewalls
            - Linux systems
            - Network appliances
        - No agent, just configure the device to point to Splunk or a syslog

    - b) API-Based Ingestion
        - Pull or receive logs via APIs
        - Examples:
            - Cloud platforms (AWS, Cloudtrail, Azure Monitor)
            - SaaS apps (Okta, Google Workspace)
        - In Splunk:
            - Uses add-ons or HTTP Event Collector (HEC)
                - **Dominant method for cloud / SaaS logs
        
    - c) File / Network Shares
        - SIEM reads logs from:
            - Shared drives (SMB / NFS)
            - Mounted directories
        - Less common, may be in legacy setups

    - d) Database Connectors
        - pull logs from databases
        - Example: Application logs stored in SQL tables

    - e) HTTP / Webhook Ingestion
        - Send logs over HTTP(S)
        - In Splunk:
            - HTTP Event Collector (HEC)
            - Very flexible - modern apps often push JSON logs this way

    - f) Streaming Pipelines
        - Tools like Kafka act as intermediaries
        - Flow: App -> Kafka -> Splunk / Elastic
        - **Useful for high-scale, distributed architectures

# 2. Normalization & Enrichment

raw logs -> normalize -> sigma -> convert -> SIEM query -> detection

## Normalization
make sure all ingested data follows a consistent schema so "apples" to "apples" can be compared.

With most SIEMs normalization happens at INGEST Time not search time like SPlunk
- this is referred to as <u>Schema-on-write</u> vs <u>Schema-on-read</u>

Splunk: Store first --> Normalize later
- raw data stored
- structure applied at search time
- flexible, but heavier queries

Other Siems: Normalize first --> then store
- data is structured before indexing
- faster queries
- less flexible if parsing is wrong


Field Extraction (parsing)
- Turning raw logs into fields:
- Technical parsing Happens on Heavy Forwarder or Indexer
- Extracts fields from raw log

```
"src=10.0.0.1 dst=8.8.8.8"
-> src=10.0.0.1, dst=8.8.8.8 
```
Happens at:
- Index-time (indexers or HFs)
- Search-time (very common)

CIM Normalization (occurs at search time on the Search Head )

- Splunk Common Information Model (CIM)
- Maps data into a standard schema
- Maps fields into a standard model
    - src_ip, source_address, client_ip --> src

Normalization standard
- Elastic Common Schema (ECS) - Elastic
- Splunk Common Information Model (CIM) - Splunk
- Azure Sentinel Information Model (ASIM) - Sentinel

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

- <u>Event Classification:</u> Similar activities from different vendors are assigned a standard category
    - for example `failed login` (windows), `denied access` (linux) --> `authentication_failure`  

#### Normalizing example
> A. normalize at ingestion (best practice), transform logs as they come in
> B. Normalize at query time, slower, messier use field aliases in queries
```
raw_log.process = "cmd.exe"

→ transform →

process.name = "cmd.exe"
```

##### Tools
- Splunk: props.conf + transforms.conf
- Sentinel: KQL parsers / ASIM functions
- Elastic: Ingest pipelines


> With sigma can field map during conversion with sigmac or unicoder.io

```
fieldmappings:
  Image: process.name
  ParentImage: process.parent.name
```

##### Build a "Detection Data Model"

internal schema
```
process_name
parent_process
cmdline
src_ip
dst_ip
dns_query
```

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
