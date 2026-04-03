This is created to keep a running list of vulnerabilities:

Ideal Workflow:
- 1. Research vulnerability (cve)
- 2. Determine signals & IoCs
    - What type of logs will generate relevant info
    - Map to index, sourcetype
- 3. Create detections

### log4Shell - CVE-2021-44228
- Software: Apache Log4j
- Impact: CVSS 10.0
- Info:
    - Log4j is embedded in thousands of Java apps (often indirectly)
    - Easy remote code execution with simple string injection
- Affected: Cloud services, enterprise apps, Minecraft servers, etc.

### ProxyLogon - CVE-2021-26855
- Software: Microsoft Exchange Server
- Impact: Allowed attackers to access email and install web shell
- Info:
    - Exchange servers exposed to the internet
    - Many orgs delayed patching
- Affected: Governments, SMBs, enterprises globally

### Heartbleed - CVE-2014-0160
- Software: OpenSSL
- Impact: Leaked sensitive memory (passwords, private keys)
- Info:
    - OpenSSL uses in a massive portion of the web
- Affected: Millions of website and services

### EternalBlue - CVE-2017-0144
- Software: Windows SMBv1
- Impact: Wormable exploit used in ransomware outbreaks
- Info:
    - Unpatched Windows systems
    - Self-propagating malware
    - Related event: WannaCry ransomeware
- Affected: Hospitals, telecoms, governments

### Shellshock - CVE-2014-6271
- Software: Bash shell (Linux / Unix)
- Impact: Remote command execution via environment variables
- Info:
    - Bash is a native program on most Linux systems
- Affected: Web servers, IoT devices

### Spring4Shell - CVE-2022-22965
- Software: Spring Framework
- Impact: Remote code execution under certain conditions
- Info:
    - Spring framework is use heavily in enterprise Java apps
- Affected: Java applications

### MOVEit Transfer - CVE-2023-34362
- Software: MOVEit Transfer
- Impact: Data exfiltration at scale
- Info:
    - Used by enterprises for file sharing
- Affected: Hundreds of organizations via supply chain-style breach

### Citrix Bleed - CVE-2023-4966
- Software: Citrix NetScaler (Netscaler ADC (application delivery controller))
- Impact: Session token theft --> account takeover
- Info:
    - Edge devices that are exposed to the internet
- Affected: Physical devices (MPX, SDX), Virtual Software (VPX), lightweight containerized (CPX)

### Confluence OGNL (object-graph navigation language) Injection - CVE-2022-26134
- Software: Atlassian Confluence
- Impact: Unauthenticated RCE
- Info: 
    - Internet-facing Confluence servers
- Affected: Enterprises, dev teams

### Follina - CVE-2022-30190
- Software: Microsoft Office / Windows
- Impact: Code exection via malicious documents
- Info:
    - phishing-friendly attack vector
- Affected: organizations via email attacks

